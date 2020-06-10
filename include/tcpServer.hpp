#ifndef TCP_SERVER_H_GUARD
#define TCP_SERVER_H_GUARD

#include "tcpSocketLib.h"
#include <string>
#include <map>
#include <list>

namespace tcpsrv
{

class Message
{
public:
  Message() : _header(NULL), _payload(NULL), _buffer(NULL), _header_size(0), _alloc_header_size(0),
    _payload_size(0), _alloc_payload_size(0), _buffer_size(0) { InitMsgBuffer(); };
  ~Message()
  {
    if (_header)   { free(_header ); }
    if (_payload)  { free(_payload); }
  };

  // custom type to tag the message
  void SetMsgType(unsigned char type /* 1B */);
  // Note: the buffer will be part of the message, must be managed outside
  void SetMsgContents(unsigned char *buffer, long size);

  unsigned char GetMsgType();
  unsigned char *GetMsgContents(long &size);

  int SignMsg(tsl_identity_t *id);
  int VerifyMsg(tsl_identity_t *peer);
  int HmacSignMsg(tsl_identity_t *id);
  int HmacVerifySignMsg(tsl_identity_t *peer);
  int CipherMsg(tsl_identity_t *id);
  int DecipherMsg(tsl_identity_t *id);

private:
  void tcpsrv::Message::InitMsgBuffer();

  unsigned char *_header;
  long _header_size, _alloc_header_size;
  unsigned char *_buffer;
  long _buffer_size;
  unsigned char *_payload; // contains all that is sent
  long _payload_size, _alloc_payload_size;
};

class IEntity
{
public:
  IEntity() : _name("local"), _addr("localhost"), _port(-1), _id(tsl_alloc_identity())
    { tsl_id_create_keys(_id, (tsl_csr_fields_t){}); };
  IEntity(IEntity &e) : _name(e._name), _addr(e._addr), _port(e._port), _id(e._id)
    { };
  IEntity(std::string name, std::string addr, int port) :
    _name(name), _addr(addr), _port(port), _id(NULL)
    { tsl_id_create_keys(_id, (tsl_csr_fields_t){}); };
  ~IEntity() { if (_id) { tsl_free_identity(_id); } } ;

  std::string GetName() { return _name; }
  std::string GetAddr() { return _addr; }
  int GetPort() { return _port; }
  tsl_identity_t *GetId() { return _id; }

protected:
  std::string _name; 
  std::string _addr; 
  int _port;
  tsl_identity_t *_id;
};

class Entity : private IEntity
{
public:
  int CreateId(); // self signed cert
  int CreateId(tsl_identity_t *ca); // certifies the key (must be the CA)
  int VerifyId(const char *ca_cert_path);

  // keys must be in LOCAL_KEYS/_name.*
  int LoadId();

private:
  const char *LOCAL_KEYS = "local_keys/";
};

class RemoteEntity : private IEntity
{
public:
  // public key and/or cert must be in LOCAL_KEYS/_name.*
  int LoadId();
  int VerifyId(tsl_identity_t *ca);
  int CipherMsg();
  int DecipherMsg();
  int SignMsg();
  int VerifyMsg();
  int HmacSign();
  int HmacVerity();

private:
  std::string _name; 
  std::string _addr; 
  int _port;
  tsl_identity_t *_id;
};

struct ConnectionStats
{
public:
  RemoteEntity _remote;
  float _lastLatency;
  float _avgLatency;
  long _nbMeasures;
  int _lastError;
  const char *_errors[4] =
  {
    "No error",
    "Out of memory for connections",
    "Wrong address format",
    "Recipient socket is not listening"
  };
};

class Connection
{
public:
  Connection() : _local(new Entity()) { };
  Connection(Entity *local) : _local(local) { };
  ~Connection() { delete _local;};

  int ConectTo(RemoteEntity *re); // stores info of connection
  int ConectTo(std::string name);

  int SendMsg(unsigned char *buffer, long size);

private:
  Entity *_local;
  // name, entity
  std::map<std::string, ConnectionStats> _conn;
};

typedef int(*ProcessMsg_t)(Connection &conn, unsigned char *buffer, long size);

class Server
{
public:
  Server() : _port(-1), _conn(new Entity()) { Start(); }; // random port
  Server(Entity *id) : _port(-1), _conn(id) { Start(); };
  Server(Entity *id, int port) : _port(port), _conn(id) { Start(); };
  ~Server();

  int AddCallback(unsigned char msgType, ProcessMsg_t clbk);
  int SendMsg(std::string name);

private:

  int Start();

  int _port;
  Connection _conn;
  std::map<unsigned char, std::list<ProcessMsg_t>> _clbks;
};



}

#endif /* TCP_SERVER_H_GUARD */
