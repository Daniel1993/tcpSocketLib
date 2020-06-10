#include "tcpServer.hpp"
#include "../deps/threading/src/util.h"
#include <stdint.h>

#define FIRST_ALLOC_SIZE 4096

enum MSG_FLAGS {
  MSG_FLAG_HAS_HMAC         = 0b00000001,
  MSG_FLAG_IS_CIPHERED      = 0b00000010,
  MSG_FLAG_HAS_SIGNATURE    = 0b10000000 // variable sizes to the end
};

typedef struct {
  uint32_t header_size;
  uint32_t cnt_size;
  uint32_t msg_type;
  uint32_t msg_flags;
  // header stuff
  // optional HMAC
  // optional signature (variable size)
} __attribute__((packed)) msg_header_t;

void tcpsrv::Message::InitMsgBuffer()
{
  if (_alloc_header_size == 0) {
    _alloc_header_size = FIRST_ALLOC_SIZE;
    _header_size = sizeof(msg_header_t);
    malloc_or_die(_header, FIRST_ALLOC_SIZE);

    msg_header_t *header = (msg_header_t*)_header;
    header->header_size = sizeof(msg_header_t);
    header->cnt_size = 0;
    header->msg_type = 0;
    header->msg_flags = 0;
  }
  if (_alloc_payload_size == 0) {
    _alloc_payload_size = FIRST_ALLOC_SIZE;
    malloc_or_die(_payload, FIRST_ALLOC_SIZE);
  }
}

void tcpsrv::Message::SetMsgType(unsigned char type)
{
  msg_header_t *header = (msg_header_t*)_header;
  header->msg_type = type;
}

void tcpsrv::Message::SetMsgContents(unsigned char *buffer, long size)
{
  _buffer_size = size;
  if (_alloc_payload_size < size + _header_size) {
    _alloc_payload_size <<= 1;
    realloc_or_die(_payload, _alloc_payload_size);
    _payload_size = _buffer_size + _header_size;
  }
  msg_header_t *header = (msg_header_t*)_header;
  header->cnt_size = _buffer_size;
}

unsigned char tcpsrv::Message::GetMsgType()
{
  msg_header_t *header = (msg_header_t*)_header;
  return header->msg_type;
}

unsigned char *tcpsrv::Message::GetMsgContents(long &size)
{
  msg_header_t *header = (msg_header_t*)_header;
  size = _buffer_size;
  return _buffer;
}

int tcpsrv::Message::SignMsg(tsl_identity_t *id)
{
  msg_header_t *header = (msg_header_t*)_header;
  if (header->msg_flags & MSG_FLAG_HAS_SIGNATURE) {
    return -1; // already signed
  }
  if (header->msg_flags & MSG_FLAG_HAS_HMAC) {
    return -2; // does not realloc the signature
  }
  unsigned char buffer[FIRST_ALLOC_SIZE];
  size_t size;
  tsl_id_sign(id, _buffer, _buffer_size, buffer, &size);
  if (header->header_size + size > _alloc_header_size) {
    _alloc_header_size <<= 1;
    realloc_or_die(_header, _alloc_header_size);
    header = (msg_header_t*)_header;
    _header_size += size;
    header->header_size += size;
  }
  uintptr_t sign_ptr = ((uintptr_t)_header) + sizeof(msg_header_t);
  memcpy((void*)sign_ptr, buffer, size);

  header->msg_flags |= MSG_FLAG_HAS_SIGNATURE;
  return 0;
}

int tcpsrv::Message::VerifyMsg(tsl_identity_t *peer)
{
  msg_header_t *header = (msg_header_t*)_header;
  uintptr_t start_ptr = ((uintptr_t)_header) + sizeof(msg_header_t);
  size_t signature_size = header->header_size - sizeof(msg_header_t);
  if (!(header->msg_flags & MSG_FLAG_HAS_SIGNATURE)) {
    return -1; // there is no signature
  }
  if (header->msg_flags & MSG_FLAG_HAS_HMAC) {
    return -2; // not supported
  }
  return tsl_id_verify(peer, (void*)start_ptr, signature_size, _buffer, _buffer_size);
}

int tcpsrv::Message::HmacSignMsg(tsl_identity_t *id)
{
  msg_header_t *header = (msg_header_t*)_header;
  if (header->msg_flags & MSG_FLAG_HAS_HMAC) {
    return -1; // already here
  }
  if (header->msg_flags & MSG_FLAG_HAS_SIGNATURE) {
    return -2; // does not realloc
  }
  unsigned char buffer[FIRST_ALLOC_SIZE];
  size_t size;
  tsl_id_hmac(id, _buffer, _buffer_size, buffer, &size);
  if (header->header_size + size > _alloc_header_size) {
    _alloc_header_size <<= 1;
    realloc_or_die(_header, _alloc_header_size);
    header = (msg_header_t*)_header;
    _header_size += size;
    header->header_size += size;
  }
  uintptr_t sign_ptr = ((uintptr_t)_header) + sizeof(msg_header_t);
  memcpy((void*)sign_ptr, buffer, size);
  header->msg_flags |= MSG_FLAG_HAS_HMAC;
  return 0;
}

int tcpsrv::Message::HmacVerifySignMsg(tsl_identity_t *peer)
{
  msg_header_t *header = (msg_header_t*)_header;
  if (header->msg_flags & MSG_FLAG_HAS_HMAC) {
    return -1; // already here
  }
  if (header->msg_flags & MSG_FLAG_HAS_SIGNATURE) {
    return -2; // does not realloc
  }
  unsigned char buffer[FIRST_ALLOC_SIZE];
  size_t size;
  tsl_id_hmac(peer, _buffer, _buffer_size, buffer, &size);
  uintptr_t sign_ptr = ((uintptr_t)_header) + sizeof(msg_header_t);
  memcpy((void*)sign_ptr, buffer, size);

  for (int i = 0; i < TSL_HASH_SIZE; ++i) {
    if (((uint8_t*)sign_ptr)[i] != ((uint8_t*)buffer)[i]) return 0;
  }
  return 1;
}

int tcpsrv::Message::CipherMsg(tsl_identity_t *id)
{
  unsigned char *buffer, *buffer_tmp;
  size_t size;
  msg_header_t *header = (msg_header_t*)_header;

  malloc_or_die(buffer, header->cnt_size * 4);

  tsl_id_sym_cipher(id, _buffer, _buffer_size, buffer, &size);

  buffer_tmp = _buffer;
  _buffer = buffer;
  _buffer_size = size;

  free(buffer_tmp);
  return 0;
}

int tcpsrv::Message::DecipherMsg(tsl_identity_t *id)
{
  unsigned char *buffer, *buffer_tmp;
  size_t size;
  msg_header_t *header = (msg_header_t*)_header;

  malloc_or_die(buffer, header->cnt_size * 4);

  tsl_id_sym_decipher(id, _buffer, _buffer_size, buffer, &size);

  buffer_tmp = _buffer;
  _buffer = buffer;
  _buffer_size = size;

  free(buffer_tmp);
  return 0;
}

int tcpsrv::Entity::CreateId()
{
  tsl_id_create_keys(_id, (tsl_csr_fields_t){});
  return 0;
}

int tcpsrv::Server::Start()
{
  char port[64] = "0";
  if (_port != -1) { sprintf(port, "%i", _port); }
  int ret = tsl_init(NULL);
  if (ret) return ret;
  _port = tsl_check_port();
}
