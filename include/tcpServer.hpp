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
  IEntity() :
    _name("local"),
    _localPrivKeys(_name + "_key_priv/"),
    _localPublKeys(_name + "_key_publ/"),
    _addr("localhost"),
    _port(-1),
    _id(tsl_alloc_identity())
    { memset((void*)&_iss, 0, sizeof(_iss)); memset((void*)&_sub, 0, sizeof(_sub)); };

  IEntity(const IEntity &e) :
    _name(e._name),
    _localPrivKeys(e._localPrivKeys),
    _localPublKeys(e._localPublKeys),
    _addr(e._addr),
    _port(e._port),
    _id(tsl_alloc_identity()) // does not copy
    { memcpy((void*)&_iss, (void*)&e._iss, sizeof(_iss)); memcpy((void*)&_sub, (void*)&e._sub, sizeof(_sub)); };

  IEntity(void *buffer, size_t len) : IEntity()
    { tsl_id_deserialize_ec_pubkey(_id, buffer, len); };

  IEntity(std::string name) : IEntity()
    { _name = name; _localPrivKeys = _name + "_key_priv/"; _localPublKeys = _name + "_key_publ/"; };

  IEntity(std::string name, std::string addr, int port) : IEntity(name)
    { _addr = addr; _port = port; };

  ~IEntity() { if (_id) { tsl_free_identity(_id); _id = NULL; } } ;

  void SetLocalPrivKeys(std::string localPrivKeys) { _localPrivKeys = localPrivKeys; }
  void SetLocalPublKeys(std::string localPublKeys) { _localPublKeys = localPublKeys; }

  std::string GetName() { return _name; }
  std::string GetAddr() { return _addr; }
  int GetPort() { return _port; }

  tsl_identity_t *GetId() { return _id; }
  void SerlKey(void *buf, size_t *l)
    { tsl_err_flag = 0; *l = tsl_id_serialize_ec_pubkey(_id, buf, *l); if (tsl_err_flag) throw TSLError(); }
  void DeserlKey(void *buffer, size_t len)
    { if (tsl_id_deserialize_ec_pubkey(_id, buffer, len)) throw TSLError(); }

  void SetIssuerCountry(std::string c)      { memcpy(_iss.country,    (void*)c.c_str(), strnlen(c.c_str(), 127)+1); };
  void SetIssuerState(std::string c)        { memcpy(_iss.state,      (void*)c.c_str(), strnlen(c.c_str(), 127)+1); };
  void SetIssuerLocal(std::string c)        { memcpy(_iss.locality,   (void*)c.c_str(), strnlen(c.c_str(), 127)+1); };
  void SetIssuerCommonName(std::string c)   { memcpy(_iss.commonName, (void*)c.c_str(), strnlen(c.c_str(), 127)+1); };
  void SetIssuerOrganization(std::string c) { memcpy(_iss.org,        (void*)c.c_str(), strnlen(c.c_str(), 127)+1); };
  void SetIssuerOrgUnit(std::string c)      { memcpy(_iss.unit,       (void*)c.c_str(), strnlen(c.c_str(), 127)+1); };

  void SetSubjectCountry(std::string c)      { memcpy(_sub.country,    (void*)c.c_str(), strnlen(c.c_str(), 127)+1); };
  void SetSubjectState(std::string c)        { memcpy(_sub.state,      (void*)c.c_str(), strnlen(c.c_str(), 127)+1); };
  void SetSubjectLocal(std::string c)        { memcpy(_sub.locality,   (void*)c.c_str(), strnlen(c.c_str(), 127)+1); };
  void SetSubjectCommonName(std::string c)   { memcpy(_sub.commonName, (void*)c.c_str(), strnlen(c.c_str(), 127)+1); };
  void SetSubjectOrganization(std::string c) { memcpy(_sub.org,        (void*)c.c_str(), strnlen(c.c_str(), 127)+1); };
  void SetSubjectOrgUnit(std::string c)      { memcpy(_sub.unit,       (void*)c.c_str(), strnlen(c.c_str(), 127)+1); };

  void CreateKeyPair(int secStrength) { tsl_id_create_keys(_id, secStrength, _sub); tsl_id_create_self_signed_cert(_id, 9999, _sub); }
  void CertKey(IEntity &e, long days) { tsl_id_cert(_id, e._id, days, _sub); }

  int VerifyId(const char *ca_cert_path);
  int VerifyId(tsl_identity_t *ca);

  int StoreId();
  int LoadId();

protected:
  std::string _name; 
  std::string _localPrivKeys;
  std::string _localPublKeys;
  std::string _addr; 
  int _port;
  tsl_identity_t *_id;
  tsl_csr_fields_t _iss;
  tsl_csr_fields_t _sub;
};

class Entity : public IEntity
{
public:

  Entity() { };
  Entity(void *buffer, size_t len) : IEntity(buffer, len) { };
  Entity(const IEntity &e) : IEntity(e) { };
  Entity(std::string name) : IEntity(name) { };
  Entity(std::string name, std::string addr, int port) : IEntity(name, addr, port) { };
  ~Entity() { };

};

class RemoteEntity : public IEntity
{
public:

  RemoteEntity() { };
  RemoteEntity(void *buffer, size_t len) { };
  RemoteEntity(const IEntity &e) { };
  RemoteEntity(std::string name) { };
  RemoteEntity(std::string name, std::string addr, int port) { };
  ~RemoteEntity() { };

  // public key and/or cert must be in LOCAL_KEYS/_name.*
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
