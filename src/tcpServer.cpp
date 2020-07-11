#include "tcpServer.hpp"
#include "../deps/threading/src/util.h"
#include <stdint.h>
#include <errno.h>
#include <limits>

#define FIRST_ALLOC_SIZE 4096
#define DAYS_VALID       365

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

void tcpsrv::Message::InitBuffer()
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

void tcpsrv::Message::SetType(unsigned char type)
{
  msg_header_t *header = (msg_header_t*)_header;
  header->msg_type = type;
}

void tcpsrv::Message::SetContents(unsigned char *buffer, long size)
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

unsigned char tcpsrv::Message::GetType()
{
  msg_header_t *header = (msg_header_t*)_header;
  return header->msg_type;
}

unsigned char *tcpsrv::Message::GetContents(long &size)
{
  msg_header_t *header = (msg_header_t*)_header;
  size = header->cnt_size;
  return _buffer;
}

unsigned char *tcpsrv::Message::GetPayload(long &size)
{
  msg_header_t *header = (msg_header_t*)_header;
  size = header->cnt_size + header->header_size;
  return _payload;
}

int tcpsrv::Message::Sign(tsl_identity_t *id)
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

int tcpsrv::Message::Verify(tsl_identity_t *peer)
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

int tcpsrv::Message::HmacSign(tsl_identity_t *id)
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

int tcpsrv::Message::HmacVerify(tsl_identity_t *peer)
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

int tcpsrv::Message::Cipher(tsl_identity_t *id)
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

int tcpsrv::Message::Decipher(tsl_identity_t *id)
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

int tcpsrv::Message::RespondWith(Message &msg)
{
  void *buffer;
  long len;
  buffer = msg.GetPayload(len);
  tsl_last_error_flag = 0;
  _respondWith(buffer, len);
  if (tsl_last_error_flag) throw tcpsrv::TSLError();
  return 0;
}

tcpsrv::Message tcpsrv::Message::WaitResponse()
{
  unsigned char buffer[FIRST_ALLOC_SIZE << 2];
  size_t len = FIRST_ALLOC_SIZE << 2;
  tsl_last_error_flag = 0;
  _waitResponse(buffer, &len);
  if (tsl_last_error_flag) throw tcpsrv::TSLError();
  return tcpsrv::Message(buffer, len);
}

// internal use only
int tcpsrv::Message::SetRespondWith(void(*respondWith)(void*,size_t))
{
  _respondWith = respondWith;
  return 0;
}

int tcpsrv::Message::SetWaitResponse(void(*waitResponse)(void*,size_t*))
{
  _waitResponse = waitResponse;
  return 0;
}

int tcpsrv::Entity::CreateId(int secStrength)
{
  std::string location = _localKeys;
  tsl_id_create_keys(_id, secStrength, (tsl_csr_fields_t){});
  tsl_id_create_self_signed_cert(_id, 365, (tsl_csr_fields_t){});
  return tsl_store_identity(_id,
    (location + _name + ".priv_key").c_str(),
    (location + _name + ".publ_key").c_str(),
    (location + _name + ".csr").c_str(),
    (location + _name + ".cert").c_str(),
    (location + _name + ".ca").c_str()
  );
}

int tcpsrv::Entity::CreateId(tsl_identity_t *ca, int secStrength)
{
  std::string location = _localKeys;
  tsl_id_create_keys(_id, secStrength, (tsl_csr_fields_t){});
  tsl_id_cert(ca, _id, DAYS_VALID, (tsl_csr_fields_t){});
  return tsl_store_identity(_id,
    (location + _name + ".priv_key").c_str(),
    (location + _name + ".publ_key").c_str(),
    (location + _name + ".csr").c_str(),
    (location + _name + ".cert").c_str(),
    (location + _name + ".ca").c_str()
  );
}

int tcpsrv::Entity::LoadId()
{
  std::string location = _localKeys;

  return tsl_load_identity(_id,
    (location + _name + ".priv_key").c_str(),
    (location + _name + ".publ_key").c_str(),
    (location + _name + ".csr").c_str(),
    (location + _name + ".cert").c_str(),
    (location + _name + ".ca").c_str()
  );
}

int tcpsrv::RemoteEntity::VerifyId(tsl_identity_t *ca)
{
  const char **err_str = NULL;
  int ret = tsl_id_cert_verify(_id, ca, err_str);
  if (err_str != NULL) printf("tcpsrv::RemoteEntity::VerifyId: %s\n", *err_str);
  return ret;
}

int tcpsrv::RemoteEntity::PairWithKey(tsl_identity_t *pair)
{
  _pairKey = pair;
  tsl_id_gen_peer_secret(_id, _pairKey);
  tsl_id_load_secret(_id, NULL);
  return 0;
}

int tcpsrv::RemoteEntity::CipherMsg(tcpsrv::Message &msg)
{
  return msg.Cipher(_id);
}

int tcpsrv::RemoteEntity::DecipherMsg(tcpsrv::Message &msg)
{
  return msg.Decipher(_id);
}

int tcpsrv::RemoteEntity::SignMsg(tcpsrv::Message &msg)
{
  return msg.Sign(_id);
}

int tcpsrv::RemoteEntity::VerifyMsg(tcpsrv::Message &msg)
{
  return msg.Verify(_id);
}

int tcpsrv::RemoteEntity::HmacSignMsg(tcpsrv::Message &msg)
{
  return msg.HmacSign(_id);
}

int tcpsrv::RemoteEntity::HmacVerityMsg(tcpsrv::Message &msg)
{
  return msg.HmacVerify(_id);
}

int tcpsrv::Connection::ConectTo(RemoteEntity re)
{
  char port[64] = "0";
  sprintf(port, "%i", re.GetPort());
  _conn[re.GetName()] = re;
  // TODO: _stat
  if (_currentConn > 0) tsl_close_all_connections(); // TODO: this closes all connections
  _currentConn = tsl_connect_to((char*)re.GetAddr().c_str(), (char*)port);
  if (_currentConn < 0) throw tcpsrv::TSLConnError(-1 * _currentConn);
  return _currentConn;
}

int tcpsrv::Connection::ConectTo(std::string name)
{
  auto find = _conn.find(name);
  char port[64] = "0";
  if (find == _conn.end()) return -1;
  if (_currentConn > 0) tsl_close_all_connections(); // TODO: this closes all connections
  sprintf(port, "%i", find->second.GetPort());
  _currentConn = tsl_connect_to((char*)find->second.GetAddr().c_str(), (char*)port);
  if (_currentConn < 0) throw tcpsrv::TSLConnError(-1 * _currentConn);
  return _currentConn;
}

int tcpsrv::Connection::SendMsg(tcpsrv::Message msg)
{
  void *payload;
  long len;
  if (_currentConn < 1) return -1;
  
  // TODO: use flags to auto sign/cypher

  payload = msg.GetPayload(len);
  tsl_send_msg(_currentConn, payload, len);
  return 0;
}

static int isHandlerSet = 0;
static tcpsrv::ProcessMsg_t clbks[std::numeric_limits<unsigned char>::max()];

static void server_handler(
  void *buffer,
  size_t len,
  void(*respondWith)(void*,size_t),
  void(*waitResponse)(void*, size_t*)
) {
  tcpsrv::Message msg((unsigned char*)buffer, len);
  msg.SetRespondWith(respondWith);
  msg.SetWaitResponse(waitResponse);

  // TODO: use flags to auto sign/cypher

  uint32_t type = msg.GetType();
  switch (type) {
    case 0x101: // Identity export
      break;
    // case 0x1XX: // TODO: control messages 
    default:
      if (clbks[type]) clbks[type](msg);
      break;
  }
} 

int tcpsrv::Server::Start()
{
  char port[64] = "0";
  if (_port != -1) { sprintf(port, "%i", _port); }
  tsl_init(port);
  _port = tsl_check_port();
  if (!isHandlerSet) {
    tsl_add_handler(server_handler);
    isHandlerSet = 1;
  }
  return _port;
}


int tcpsrv::Server::AddCallback(unsigned char msgType, tcpsrv::ProcessMsg_t clbk)
{
  int ret = clbks[msgType] != NULL;
  clbks[msgType] = clbk;
  return ret;
}

int tcpsrv::Server::SendMsg(tcpsrv::RemoteEntity re, tcpsrv::Message msg)
{
  _conn.ConectTo(re);
  return _conn.SendMsg(msg);
}

int tcpsrv::Server::SendMsg(std::string name, tcpsrv::Message msg)
{
  _conn.ConectTo(name);
  return _conn.SendMsg(msg);
}

int tcpsrv::Server::SendMsg(tcpsrv::Message msg)
{
  return _conn.SendMsg(msg);
}
