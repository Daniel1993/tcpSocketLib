#ifndef TCP_SERVER_H_GUARD
#define TCP_SERVER_H_GUARD

#include "tcpSocketLib.h"
#include <string>
#include <map>
#include <list>
#include <exception>

namespace tcpsrv
{

class TSLError : public std::exception
{
  virtual const char* what() const throw()
  {
    return (const char*)tsl_last_error_msg;
  }
};

class Message
{
public:
  Message() : _header(NULL), _payload(NULL), _buffer(NULL), _header_size(0), _alloc_header_size(0),
    _payload_size(0), _alloc_payload_size(0), _buffer_size(0) { InitBuffer(); };
  Message(unsigned char *buffer, size_t len) : _header(NULL), _payload(NULL), _buffer(NULL),
    _header_size(0), _alloc_header_size(0), _payload_size(0), _alloc_payload_size(0), _buffer_size(0)
    { InitBuffer(); SetContents(buffer, len); };
  ~Message()
  {
    if (_header)   { free(_header ); }
    if (_payload)  { free(_payload); }
  };

  // custom type to tag the message
  void SetType(unsigned char type /* 1B */);
  // Note: the buffer will be part of the message, must be managed outside
  void SetContents(unsigned char *buffer, long size);

  unsigned char GetType();
  unsigned char *GetContents(long &size);
  unsigned char *GetPayload(long &size);

  int Sign(tsl_identity_t *id);
  int Verify(tsl_identity_t *peer);
  int HmacSign(tsl_identity_t *id);
  int HmacVerify(tsl_identity_t *peer);
  int Cipher(tsl_identity_t *id);
  int Decipher(tsl_identity_t *id);

  int RespondWith(Message &msg);
  Message WaitResponse();

  // internal use only
  int SetRespondWith(void(*respondWith)(void*,size_t));
  int SetWaitResponse(void(*waitResponse)(void*,size_t*));

private:
  void InitBuffer();

  unsigned char *_header;
  unsigned char *_payload; // contains all that is sent
  unsigned char *_buffer;
  long _header_size;
  long _alloc_header_size;
  long _payload_size;
  long _alloc_payload_size;
  long _buffer_size;
  void(*_respondWith)(void*,size_t);
  void(*_waitResponse)(void*, size_t*);
};

class IEntity
{
public:
  IEntity() : _localKeys("local_keys/"), _name("local"), _addr("localhost"), _port(-1), _id(tsl_alloc_identity())
    { tsl_id_create_keys(_id, 1, (tsl_csr_fields_t){}); };
  IEntity(void *buffer, size_t len) : _name("local"), _addr("localhost"), _port(-1), _id(tsl_alloc_identity())
    { tsl_id_deserialize_ec_pubkey(_id, buffer, len); };
  IEntity(const IEntity &e) : _name(e._name), _addr(e._addr), _port(e._port), _id(e._id)
    { };
  IEntity(std::string &name, std::string &addr, int port = 0) :
    _name(name), _addr(addr), _port(port), _id(NULL)
    { tsl_id_create_keys(_id, 1, (tsl_csr_fields_t){}); };
  ~IEntity() { if (_id) { tsl_free_identity(_id); } } ;

  void SetLocalKeys(std::string localKeys) { _localKeys = localKeys; }
  tsl_identity_t *GetId() { return _id; };
  std::string GetName() { return _name; }
  std::string GetAddr() { return _addr; }
  int GetPort() { return _port; }
  void SerlKey(void *buffer, size_t *len)
  {
    tsl_last_error_flag = 0;
    *len = tsl_id_serialize_ec_pubkey(_id, buffer, *len);
    if (tsl_last_error_flag) throw TSLError();
  }
  void DeserlKey(void *buffer, size_t len)
  {
    if (tsl_id_deserialize_ec_pubkey(_id, buffer, len))
      throw TSLError();
  }
  // keys must be in LOCAL_KEYS/_name.*
  int LoadId();

protected:
  std::string _localKeys; // = "local_keys/";
  std::string _name; 
  std::string _addr; 
  int _port;
  tsl_identity_t *_id;
};

class Entity : public IEntity
{
public:
  int CreateId(int secStrength); // self signed cert
  int CreateId(tsl_identity_t *ca, int secStrength); // certifies the key (must be the CA)
  int VerifyId(const char *ca_cert_path);
};

class RemoteEntity : public IEntity
{
public:
  // public key and/or cert must be in LOCAL_KEYS/_name.*
  int VerifyId(tsl_identity_t *ca);
  int PairWithKey(tsl_identity_t *pair);
  int CipherMsg(Message &msg);
  int DecipherMsg(Message &msg);
  int SignMsg(Message &msg);
  int VerifyMsg(Message &msg);
  int HmacSignMsg(Message &msg);
  int HmacVerityMsg(Message &msg);

private:
  tsl_identity_t *_pairKey;
};

static const char *TSLConnErrorStrs[5] =
{
  "No error",
  "Out of memory for connections",
  "Wrong address format",
  "Recipient socket is not listening",
  "Unknown connection error"
};

struct ConnectionStats
{
public:
  RemoteEntity _remote;
  float _lastLatency;
  float _avgLatency;
  long _nbMeasures;
  int _lastError;
};

class TSLConnError : public std::exception
{
public:
  TSLConnError() : _error(0) { };
  TSLConnError(int error) { _error = (error < 0 || error > 4) ? 4 : error; };

  virtual const char* what() const throw()
  {
    return (const char*)TSLConnErrorStrs[_error];
  }

  int _error;
};

class Connection
{
public:
  Connection() : _local(new Entity()), _currentConn(0) { };
  Connection(Entity *local) : _local(local), _currentConn(0) { };
  ~Connection() { delete _local;};

  int ConectTo(RemoteEntity re); // stores info of connection
  int ConectTo(std::string name);

  int SendMsg(Message msg);

private:
  Entity *_local;
  int _currentConn;
  // name, entity
  std::map<std::string, RemoteEntity> _conn;
  std::map<std::string, ConnectionStats> _stat; // TODO
};

typedef int(*ProcessMsg_t)(Message &msg);

class Server
{
public:
  Server() : _port(-1), _conn(new Entity()) { Start(); }; // random port
  Server(Entity *id) : _port(-1), _conn(id) { Start(); };
  Server(Entity *id, int port) : _port(port), _conn(id) { Start(); };
  ~Server();

  int AddCallback(unsigned char msgType, ProcessMsg_t clbk);
  int SendMsg(RemoteEntity re, Message msg);
  int SendMsg(std::string name, Message msg);
  int SendMsg(Message msg); // uses last connection

private:

  int Start();

  int _port;
  Connection _conn;
  std::map<unsigned char, std::list<ProcessMsg_t>> _clbks;
};



}

#endif /* TCP_SERVER_H_GUARD */
