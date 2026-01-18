/*
 * Copyright (C) 2026 JeaFriday (https://github.com/JeaFrid/Revani)
 * * This project is part of Revani
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See the LICENSE file in the project root for full license information.
 * * For commercial licensing, please contact: JeaFriday
 */

import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart' as encrypt;

class RevaniClient {
  final String host;
  final int port;
  final bool secure;

  Socket? _socket;
  String? _sessionKey;
  String? _accountID;
  String? _projectName;
  String? _projectID;

  late final RevaniAccount account;
  late final RevaniProject project;
  late final RevaniData data;
  late final RevaniStorage storage;
  late final RevaniLivekit livekit;
  late final RevaniPubSub pubsub;

  final StreamController<Map<String, dynamic>> _responseStream =
      StreamController.broadcast();
  final List<int> _buffer = [];

  RevaniClient({required this.host, this.port = 16897, this.secure = true}) {
    account = RevaniAccount(this);
    project = RevaniProject(this);
    data = RevaniData(this);
    storage = RevaniStorage(this);
    livekit = RevaniLivekit(this);
    pubsub = RevaniPubSub(this);
  }

  Future<void> connect() async {
    if (secure) {
      _socket = await SecureSocket.connect(
        host,
        port,
        onBadCertificate: (cert) => true,
      );
    } else {
      _socket = await Socket.connect(host, port);
    }

    _socket!.listen(
      _onData,
      onError: (e) => disconnect(),
      onDone: () => disconnect(),
    );
  }

  void _onData(Uint8List data) {
    _buffer.addAll(data);
    while (_buffer.length >= 4) {
      final header = ByteData.sublistView(
        Uint8List.fromList(_buffer.sublist(0, 4)),
      );
      final length = header.getUint32(0);

      if (_buffer.length >= length + 4) {
        final payload = _buffer.sublist(4, length + 4);
        _buffer.removeRange(0, length + 4);

        final json = jsonDecode(utf8.decode(payload));

        if (json is Map<String, dynamic> &&
            json.containsKey('encrypted') &&
            _sessionKey != null) {
          final decrypted = _decrypt(json['encrypted']);
          _responseStream.add(jsonDecode(decrypted));
        } else {
          _responseStream.add(json);
        }
      } else {
        break;
      }
    }
  }

  Future<Map<String, dynamic>> execute(
    Map<String, dynamic> command, {
    bool useEncryption = true,
  }) async {
    final payload = (useEncryption && _sessionKey != null)
        ? {'encrypted': _encrypt(jsonEncode(command))}
        : command;

    final bytes = utf8.encode(jsonEncode(payload));
    final header = ByteData(4)..setUint32(0, bytes.length);

    _socket!.add(header.buffer.asUint8List());
    _socket!.add(bytes);

    return await _responseStream.stream.first;
  }

  String _encrypt(String text) {
    final wrapper = jsonEncode({
      "payload": text,
      "ts": DateTime.now().millisecondsSinceEpoch,
    });

    final salt = encrypt.IV.fromSecureRandom(16);
    final keyBytes = sha256
        .convert(utf8.encode(_sessionKey! + salt.base64))
        .bytes;
    final key = encrypt.Key(Uint8List.fromList(keyBytes));
    final iv = encrypt.IV.fromSecureRandom(16);

    final encrypter = encrypt.Encrypter(
      encrypt.AES(key, mode: encrypt.AESMode.gcm),
    );
    final encrypted = encrypter.encrypt(wrapper, iv: iv);

    return "${salt.base64}:${iv.base64}:${encrypted.base64}";
  }

  String _decrypt(String encryptedData) {
    final parts = encryptedData.split(':');
    final salt = encrypt.IV.fromBase64(parts[0]);
    final iv = encrypt.IV.fromBase64(parts[1]);
    final cipherText = parts[2];

    final keyBytes = sha256
        .convert(utf8.encode(_sessionKey! + salt.base64))
        .bytes;
    final key = encrypt.Key(Uint8List.fromList(keyBytes));

    final encrypter = encrypt.Encrypter(
      encrypt.AES(key, mode: encrypt.AESMode.gcm),
    );
    final decrypted = encrypter.decrypt64(cipherText, iv: iv);

    final Map<String, dynamic> wrapper = jsonDecode(decrypted);
    return wrapper['payload'];
  }

  void setSession(String key) => _sessionKey = key;
  void setAccount(String id) => _accountID = id;
  void setProject(String name, String? id) {
    _projectName = name;
    _projectID = id;
  }

  String get accountID => _accountID ?? "";
  String get projectName => _projectName ?? "";
  String get projectID => _projectID ?? "";

  void disconnect() {
    _socket?.destroy();
    _socket = null;
    _sessionKey = null;
    _accountID = null;
    _projectName = null;
    _projectID = null;
  }
}

class RevaniAccount {
  final RevaniClient _client;
  RevaniAccount(this._client);

  Future<Map<String, dynamic>> create(
    String email,
    String password, [
    Map<String, dynamic>? extraData,
  ]) async {
    return await _client.execute({
      'cmd': 'account/create',
      'email': email,
      'password': password,
      'data': extraData ?? {},
    }, useEncryption: false);
  }

  Future<bool> login(String email, String password) async {
    final res = await _client.execute({
      'cmd': 'auth/login',
      'email': email,
      'password': password,
    }, useEncryption: false);

    if (res['status'] == 200) {
      _client.setSession(res['session_key']);
      final idRes = await _client.execute({
        'cmd': 'account/get-id',
        'email': email,
        'password': password,
      }, useEncryption: false);

      if (idRes['status'] == 200) {
        _client.setAccount(idRes['data']['id']);
      }
      return true;
    }
    return false;
  }

  Future<Map<String, dynamic>> getData() async {
    return await _client.execute({
      'cmd': 'account/get-data',
      'id': _client.accountID,
    });
  }
}

class RevaniProject {
  final RevaniClient _client;
  RevaniProject(this._client);

  Future<Map<String, dynamic>> use(String projectName) async {
    final res = await _client.execute({
      'cmd': 'project/exist',
      'accountID': _client.accountID,
      'projectName': projectName,
    });

    if (res['status'] == 200) {
      _client.setProject(projectName, res['id']);
    }
    return res;
  }

  Future<Map<String, dynamic>> create(String projectName) async {
    final res = await _client.execute({
      'cmd': 'project/create',
      'accountID': _client.accountID,
      'projectName': projectName,
    });
    if (res['status'] == 200) {
      _client.setProject(projectName, res['data']['id']);
    }
    return res;
  }
}

class RevaniData {
  final RevaniClient _client;
  RevaniData(this._client);

  Future<Map<String, dynamic>> add({
    required String bucket,
    required String tag,
    required Map<String, dynamic> value,
  }) async {
    return await _client.execute({
      'cmd': 'data/add',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'bucket': bucket,
      'tag': tag,
      'value': value,
    });
  }

  Future<Map<String, dynamic>> get({
    required String bucket,
    required String tag,
  }) async {
    return await _client.execute({
      'cmd': 'data/get',
      'projectID': _client.projectID,
      'bucket': bucket,
      'tag': tag,
    });
  }

  Future<Map<String, dynamic>> query({
    required String bucket,
    required Map<String, dynamic> query,
  }) async {
    return await _client.execute({
      'cmd': 'data/query',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'bucket': bucket,
      'query': query,
    });
  }

  Future<Map<String, dynamic>> update({
    required String bucket,
    required String tag,
    required dynamic newValue,
  }) async {
    return await _client.execute({
      'cmd': 'data/update',
      'projectID': _client.projectID,
      'bucket': bucket,
      'tag': tag,
      'newValue': newValue,
    });
  }

  Future<Map<String, dynamic>> delete({
    required String bucket,
    required String tag,
  }) async {
    return await _client.execute({
      'cmd': 'data/delete',
      'projectID': _client.projectID,
      'bucket': bucket,
      'tag': tag,
    });
  }
}

class RevaniStorage {
  final RevaniClient _client;
  RevaniStorage(this._client);

  Future<Map<String, dynamic>> upload({
    required String fileName,
    required List<int> bytes,
    bool compress = false,
  }) async {
    return await _client.execute({
      'cmd': 'storage/upload',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'fileName': fileName,
      'bytes': bytes,
      'compress': compress,
    });
  }

  Future<Map<String, dynamic>> download(String fileId) async {
    return await _client.execute({
      'cmd': 'storage/download',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'fileId': fileId,
    });
  }

  Future<Map<String, dynamic>> delete(String fileId) async {
    return await _client.execute({
      'cmd': 'storage/delete',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'fileId': fileId,
    });
  }
}

class RevaniLivekit {
  final RevaniClient _client;
  RevaniLivekit(this._client);

  Future<Map<String, dynamic>> init(
    String host,
    String apiKey,
    String apiSecret,
  ) async {
    return await _client.execute({
      'cmd': 'livekit/init',
      'host': host,
      'apiKey': apiKey,
      'apiSecret': apiSecret,
    });
  }

  Future<Map<String, dynamic>> autoConnect() async {
    return await _client.execute({
      'cmd': 'livekit/connect',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
    });
  }

  Future<Map<String, dynamic>> createToken({
    required String roomName,
    required String userID,
    required String userName,
    bool isAdmin = false,
  }) async {
    return await _client.execute({
      'cmd': 'livekit/create-token',
      'roomName': roomName,
      'userID': userID,
      'userName': userName,
      'isAdmin': isAdmin,
    });
  }

  Future<Map<String, dynamic>> createRoom(
    String roomName, {
    int timeout = 10,
    int maxUsers = 50,
  }) async {
    return await _client.execute({
      'cmd': 'livekit/create-room',
      'roomName': roomName,
      'emptyTimeoutMinute': timeout,
      'maxUsers': maxUsers,
    });
  }
}

class RevaniPubSub {
  final RevaniClient _client;
  RevaniPubSub(this._client);

  Future<Map<String, dynamic>> subscribe(String topic, String clientId) async {
    return await _client.execute({
      'cmd': 'pubsub/subscribe',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'clientId': clientId,
      'topic': topic,
    });
  }

  Future<Map<String, dynamic>> publish(
    String topic,
    Map<String, dynamic> data, [
    String? clientId,
  ]) async {
    return await _client.execute({
      'cmd': 'pubsub/publish',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'topic': topic,
      'data': data,
      'clientId': clientId,
    });
  }

  Future<Map<String, dynamic>> unsubscribe(
    String topic,
    String clientId,
  ) async {
    return await _client.execute({
      'cmd': 'pubsub/unsubscribe',
      'clientId': clientId,
      'topic': topic,
    });
  }
}
