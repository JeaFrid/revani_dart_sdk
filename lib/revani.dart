import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:http/http.dart' as http;

class RevaniResponse {
  final int status;
  final String message;
  final String? error;
  final dynamic data;
  final String? description;

  RevaniResponse({
    required this.status,
    required this.message,
    this.error,
    this.data,
    this.description,
  });

  bool get isSuccess => status >= 200 && status < 300;

  static RevaniResponse fromMap(Map<String, dynamic> map) {
    dynamic effectiveData = map['data'];
    if (effectiveData == null && map.containsKey('id')) {
      effectiveData = {'id': map['id']};
    }
    if (effectiveData == null && map.containsKey('session_key')) {
      effectiveData = {'session_key': map['session_key']};
    }
    if (effectiveData == null && map.containsKey('token')) {
      effectiveData = {'token': map['token']};
    }

    return RevaniResponse(
      status: map['status'] ?? 500,
      message: map['message'] ?? (map['msg'] ?? 'Unknown'),
      error: map['error'],
      data: effectiveData,
      description: map['description'],
    );
  }

  static RevaniResponse networkError(String error) {
    return RevaniResponse(
      status: 503,
      message: 'Network Error',
      error: error,
      description: 'Connection failed',
    );
  }
}

typedef SuccessCallback = void Function(dynamic data);
typedef ErrorCallback = void Function(String error);

class RevaniClient {
  final String host;
  final int port;
  final bool secure;
  final bool autoReconnect;

  Socket? _socket;
  String? _sessionKey;
  String? _accountID;
  String? _projectName;
  String? _projectID;
  String? _token;
  int _serverTimeOffset = 0;
  bool _isReconnecting = false;

  late final RevaniAccount account;
  late final RevaniProject project;
  late final RevaniData data;
  late final RevaniUser user;
  late final RevaniSocial social;
  late final RevaniChat chat;
  late final RevaniStorage storage;

  final StreamController<Map<String, dynamic>> _responseController =
      StreamController<Map<String, dynamic>>.broadcast();
  final List<int> _buffer = [];

  RevaniClient({
    required this.host,
    this.port = 16897,
    this.secure = true,
    this.autoReconnect = true,
  }) {
    account = RevaniAccount(this);
    project = RevaniProject(this);
    data = RevaniData(this);
    user = RevaniUser(this);
    social = RevaniSocial(this);
    chat = RevaniChat(this);
    storage = RevaniStorage(this);
  }

  String get httpBaseUrl => "${secure ? 'https' : 'http'}://$host:${port + 1}";

  Future<void> connect() async {
    try {
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
        onError: (e) => _handleConnectionError(e),
        onDone: () => _handleConnectionDone(),
      );
      _isReconnecting = false;
      await _syncTime();
    } catch (e) {
      if (autoReconnect) _attemptReconnect();
    }
  }

  Future<void> _syncTime() async {
    final res = await execute({'cmd': 'health'}, useEncryption: false);
    if (res.isSuccess && res.data != null && res.data['timestamp'] != null) {
      int serverTime = res.data['timestamp'];
      _serverTimeOffset = serverTime - DateTime.now().millisecondsSinceEpoch;
    }
  }

  void _attemptReconnect() async {
    if (_isReconnecting) return;
    _isReconnecting = true;
    _socket?.destroy();
    _socket = null;
    int attempts = 0;
    while (_socket == null) {
      attempts++;
      await Future.delayed(
        Duration(seconds: min(30, pow(2, attempts).toInt())),
      );
      try {
        await connect();
      } catch (_) {}
    }
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
        try {
          final jsonString = utf8.decode(payload);
          final json = jsonDecode(jsonString);
          if (json is Map<String, dynamic> &&
              json.containsKey('encrypted') &&
              _sessionKey != null) {
            final decrypted = _decrypt(json['encrypted']);
            _responseController.add(jsonDecode(decrypted));
          } else {
            _responseController.add(json);
          }
        } catch (_) {}
      } else {
        break;
      }
    }
  }

  Future<RevaniResponse> execute(
    Map<String, dynamic> command, {
    bool useEncryption = true,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) async {
    if (_socket == null) {
      final res = RevaniResponse.networkError("Not connected");
      if (onError != null) onError(res.error!);
      return res;
    }

    try {
      final responseFuture = _responseController.stream.first;
      final payload = (useEncryption && _sessionKey != null)
          ? {'encrypted': _encrypt(jsonEncode(command))}
          : command;

      final bytes = utf8.encode(jsonEncode(payload));
      final header = ByteData(4)..setUint32(0, bytes.length);

      _socket!.add(header.buffer.asUint8List());
      _socket!.add(bytes);

      final rawResponse = await responseFuture.timeout(Duration(seconds: 15));
      final response = RevaniResponse.fromMap(rawResponse);

      if (response.isSuccess) {
        if (onSuccess != null) onSuccess(response.data);
      } else {
        if (onError != null) onError(response.error ?? response.message);
      }
      return response;
    } catch (e) {
      final res = RevaniResponse.networkError(e.toString());
      if (onError != null) onError(res.error!);
      return res;
    }
  }

  String _encrypt(String text) {
    final wrapper = jsonEncode({
      "payload": text,
      "ts": DateTime.now().millisecondsSinceEpoch + _serverTimeOffset,
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

  void _handleConnectionError(dynamic e) => _attemptReconnect();
  void _handleConnectionDone() => _attemptReconnect();
  void setSession(String key) => _sessionKey = key;
  void setAccount(String id) => _accountID = id;
  void setToken(String token) => _token = token;
  void setProject(String name, String? id) {
    _projectName = name;
    _projectID = id;
  }

  String get accountID => _accountID ?? "";
  String get projectName => _projectName ?? "";
  String get projectID => _projectID ?? "";
  String get token => _token ?? "";
  bool get isSignedIn => _token != null;

  void logout() {
    _sessionKey = null;
    _accountID = null;
    _token = null;
    _socket?.destroy();
    _socket = null;
  }
}

class RevaniAccount {
  final RevaniClient _client;
  RevaniAccount(this._client);

  Future<RevaniResponse> create(
    String email,
    String password, {
    Map<String, dynamic>? data,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'account/create',
      'email': email,
      'password': password,
      'data': data ?? {},
    },
    useEncryption: false,
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> login(
    String email,
    String password, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) async {
    final res = await _client.execute({
      'cmd': 'auth/login',
      'email': email,
      'password': password,
    }, useEncryption: false);

    if (res.isSuccess && res.data != null) {
      if (res.data.containsKey('session_key')) {
        _client.setSession(res.data['session_key']);
      }
      if (res.data.containsKey('token')) {
        _client.setToken(res.data['token']);
      }
      if (res.data.containsKey('id')) {
        _client.setAccount(res.data['id']);
        if (onSuccess != null) onSuccess(res.data);
        return res;
      }
    }

    if (onError != null) onError(res.error ?? res.message);
    return res;
  }
}

class RevaniProject {
  final RevaniClient _client;
  RevaniProject(this._client);

  Future<RevaniResponse> create(
    String name, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'project/create',
      'accountID': _client.accountID,
      'projectName': name,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> use(
    String name, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) async {
    final res = await _client.execute({
      'cmd': 'project/exist',
      'accountID': _client.accountID,
      'projectName': name,
    });
    if (res.isSuccess) _client.setProject(name, res.data['id'] ?? res.data);
    if (res.isSuccess && onSuccess != null) onSuccess(res.data);
    if (!res.isSuccess && onError != null) onError(res.error ?? res.message);
    return res;
  }
}

class RevaniData {
  final RevaniClient _client;
  RevaniData(this._client);

  Future<RevaniResponse> add({
    required String bucket,
    required String tag,
    required Map<String, dynamic> value,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'data/add',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'bucket': bucket,
      'tag': tag,
      'value': value,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> get({
    required String bucket,
    required String tag,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'data/get',
      'projectID': _client.projectID,
      'bucket': bucket,
      'tag': tag,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> query({
    required String bucket,
    required Map<String, dynamic> query,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'data/query',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'bucket': bucket,
      'query': query,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> update({
    required String bucket,
    required String tag,
    required dynamic newValue,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'data/update',
      'projectID': _client.projectID,
      'bucket': bucket,
      'tag': tag,
      'newValue': newValue,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> delete({
    required String bucket,
    required String tag,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'data/delete',
      'projectID': _client.projectID,
      'bucket': bucket,
      'tag': tag,
    },
    onSuccess: onSuccess,
    onError: onError,
  );
}

class RevaniUser {
  final RevaniClient _client;
  RevaniUser(this._client);

  Future<RevaniResponse> login(
    String email,
    String password, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'user/login',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'email': email,
      'password': password,
    },
    onSuccess: onSuccess,
    onError: onError,
  );
}

class RevaniSocial {
  final RevaniClient _client;
  RevaniSocial(this._client);

  Future<RevaniResponse> createPost(
    Map<String, dynamic> postData, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'social/post/create',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'postData': postData,
    },
    onSuccess: onSuccess,
    onError: onError,
  );
}

class RevaniChat {
  final RevaniClient _client;
  RevaniChat(this._client);

  Future<RevaniResponse> create(
    List<String> participants, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'chat/create',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'participants': participants,
    },
    onSuccess: onSuccess,
    onError: onError,
  );
}

class RevaniStorage {
  final RevaniClient _client;
  RevaniStorage(this._client);

  Future<RevaniResponse> upload({
    required String fileName,
    required List<int> bytes,
    bool compress = false,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) async {
    try {
      final url = Uri.parse("${_client.httpBaseUrl}/upload");
      final response = await http.post(
        url,
        headers: {
          'x-account-id': _client.accountID,
          'x-project-name': _client.projectName,
          'x-file-name': fileName,
          'x-session-token': _client.token,
        },
        body: bytes,
      );

      final res = RevaniResponse.fromMap(jsonDecode(response.body));
      if (res.isSuccess && onSuccess != null) onSuccess(res.data);
      if (!res.isSuccess && onError != null) onError(res.error ?? res.message);
      return res;
    } catch (e) {
      final res = RevaniResponse.networkError(e.toString());
      if (onError != null) onError(res.error!);
      return res;
    }
  }

  Future<RevaniResponse> download({
    required String fileId,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) async {
    try {
      final url = Uri.parse(
        "${_client.httpBaseUrl}/file/${_client.projectID}/$fileId",
      );
      final response = await http.get(
        url,
        headers: {'x-session-token': _client.token},
      );

      if (response.statusCode == 200) {
        final res = RevaniResponse(
          status: 200,
          message: "Success",
          data: {"bytes": response.bodyBytes},
        );
        if (onSuccess != null) onSuccess(res.data);
        return res;
      } else {
        final res = RevaniResponse(
          status: response.statusCode,
          message: "Download Failed",
        );
        if (onError != null) onError(res.message);
        return res;
      }
    } catch (e) {
      final res = RevaniResponse.networkError(e.toString());
      if (onError != null) onError(res.error!);
      return res;
    }
  }
}
