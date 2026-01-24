import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:path/path.dart' as p;

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
    Map<String, dynamic> effectiveData = {};
    if (map['data'] != null && map['data'] is Map) {
      effectiveData.addAll(Map<String, dynamic>.from(map['data']));
    } else if (map['data'] != null) {
      effectiveData['payload'] = map['data'];
    }

    if (map.containsKey('id')) effectiveData['id'] = map['id'];
    if (map.containsKey('session_key')) {
      effectiveData['session_key'] = map['session_key'];
    }
    if (map.containsKey('token')) effectiveData['token'] = map['token'];

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

  Map<String, dynamic> toJson() {
    return {
      'status': status,
      'message': message,
      'error': error,
      'data': data,
      'description': description,
    };
  }
}

typedef SuccessCallback = void Function(RevaniResponse response);
typedef ErrorCallback = void Function(RevaniResponse response);

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
  late final RevaniLivekit livekit;
  late final RevaniPubSub pubsub;

  late final http.Client _httpClient;

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
    livekit = RevaniLivekit(this);
    pubsub = RevaniPubSub(this);

    final ioc = HttpClient();
    ioc.badCertificateCallback =
        (X509Certificate cert, String host, int port) => true;
    _httpClient = IOClient(ioc);
  }

  String get httpBaseUrl => "${secure ? 'https' : 'http'}://$host:${port + 1}";

  Future<void> connect() async {
    try {
      if (secure) {
        _socket = await SecureSocket.connect(
          host,
          port,
          onBadCertificate: (cert) => true,
        ).timeout(const Duration(seconds: 10));
      } else {
        _socket = await Socket.connect(
          host,
          port,
        ).timeout(const Duration(seconds: 10));
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
    try {
      final res = await execute({
        'cmd': 'health',
      }, useEncryption: false).timeout(const Duration(seconds: 2));
      if (res.isSuccess &&
          res.data != null &&
          res.data['payload'] != null &&
          res.data['payload']['ts'] != null) {
        _serverTimeOffset =
            res.data['payload']['ts'] - DateTime.now().millisecondsSinceEpoch;
      }
    } catch (_) {}
  }

  void _attemptReconnect() async {
    if (_isReconnecting) return;
    _isReconnecting = true;
    _socket?.destroy();
    _socket = null;
    await Future.delayed(const Duration(seconds: 2));
    try {
      await connect();
    } catch (_) {}
  }

  void _onData(Uint8List data) {
    _buffer.addAll(data);
    while (true) {
      if (_buffer.length < 4) break;
      final headerBytes = Uint8List.fromList(_buffer.sublist(0, 4));
      final header = ByteData.sublistView(headerBytes);
      final length = header.getUint32(0);
      if (_buffer.length >= length + 4) {
        final payload = Uint8List.fromList(_buffer.sublist(4, length + 4));
        _buffer.removeRange(0, length + 4);
        try {
          final json = jsonDecode(utf8.decode(payload));
          if (json is Map<String, dynamic> &&
              json.containsKey('encrypted') &&
              _sessionKey != null) {
            _responseController.add(jsonDecode(_decrypt(json['encrypted'])));
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
      onError?.call(res);
      return res;
    }

    try {
      final responseFuture = _responseController.stream.first;
      final payload = (useEncryption && _sessionKey != null)
          ? {'encrypted': _encrypt(jsonEncode(command))}
          : command;

      final bytes = utf8.encode(jsonEncode(payload));
      _socket!.add(
        (ByteData(4)..setUint32(0, bytes.length)).buffer.asUint8List(),
      );
      _socket!.add(bytes);

      final response = RevaniResponse.fromMap(
        await responseFuture.timeout(const Duration(seconds: 5)),
      );

      if (response.isSuccess) {
        onSuccess?.call(response);
      } else {
        onError?.call(response);
      }
      return response;
    } catch (e) {
      final res = RevaniResponse.networkError(e.toString());
      onError?.call(res);
      return res;
    }
  }

  String _encrypt(String text) {
    final wrapper = jsonEncode({
      "payload": text,
      "ts": DateTime.now().millisecondsSinceEpoch + _serverTimeOffset,
    });
    final salt = encrypt.IV.fromSecureRandom(16);
    final key = encrypt.Key(
      Uint8List.fromList(
        sha256.convert(utf8.encode(_sessionKey! + salt.base64)).bytes,
      ),
    );
    final iv = encrypt.IV.fromSecureRandom(16);
    final encrypter = encrypt.Encrypter(
      encrypt.AES(key, mode: encrypt.AESMode.gcm),
    );
    return "${salt.base64}:${iv.base64}:${encrypter.encrypt(wrapper, iv: iv).base64}";
  }

  String _decrypt(String encryptedData) {
    final parts = encryptedData.split(':');
    final key = encrypt.Key(
      Uint8List.fromList(
        sha256.convert(utf8.encode(_sessionKey! + parts[0])).bytes,
      ),
    );
    final encrypter = encrypt.Encrypter(
      encrypt.AES(key, mode: encrypt.AESMode.gcm),
    );
    return jsonDecode(
      encrypter.decrypt64(parts[2], iv: encrypt.IV.fromBase64(parts[1])),
    )['payload'];
  }

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
  bool get isSignedIn => _token != null && _token!.isNotEmpty;

  void logout() {
    _sessionKey = null;
    _accountID = null;
    _token = null;
    _socket?.destroy();
    _socket = null;
  }

  void _handleConnectionError(dynamic e) => _attemptReconnect();
  void _handleConnectionDone() => _attemptReconnect();
}

class RevaniAccount {
  final RevaniClient _client;
  RevaniAccount(this._client);

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
      if (res.data.containsKey('token')) _client.setToken(res.data['token']);
      if (res.data.containsKey('id')) {
        _client.setAccount(res.data['id']);
        onSuccess?.call(res);
        return res;
      }
    }
    onError?.call(res);
    return res;
  }

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

  Future<RevaniResponse> getData({
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'account/get-data', 'id': _client.accountID},
    onSuccess: onSuccess,
    onError: onError,
  );
}

class RevaniProject {
  final RevaniClient _client;
  RevaniProject(this._client);

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
    if (res.isSuccess) {
      _client.setProject(name, res.data['id'] ?? res.data['payload']);
      onSuccess?.call(res);
    } else {
      onError?.call(res);
    }
    return res;
  }

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

  Future<RevaniResponse> addBatch({
    required String bucket,
    required Map<String, Map<String, dynamic>> items,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'data/add-batch',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'bucket': bucket,
      'items': items,
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

  Future<RevaniResponse> getAll({
    required String bucket,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'data/get-all', 'projectID': _client.projectID, 'bucket': bucket},
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

  Future<RevaniResponse> deleteAll({
    required String bucket,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'data/delete-all',
      'projectID': _client.projectID,
      'bucket': bucket,
    },
    onSuccess: onSuccess,
    onError: onError,
  );
}

class RevaniUser {
  final RevaniClient _client;
  RevaniUser(this._client);

  Future<RevaniResponse> register(
    Map<String, dynamic> userData, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'user/register',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'userData': userData,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

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

  Future<RevaniResponse> getProfile(
    String userId, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'user/get-profile',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'userId': userId,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> editProfile(
    String userId,
    Map<String, dynamic> updates, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'user/edit-profile', 'userId': userId, 'updates': updates},
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> changePassword(
    String userId,
    String oldPass,
    String newPass, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'user/change-password',
      'userId': userId,
      'oldPass': oldPass,
      'newPass': newPass,
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

  Future<RevaniResponse> getPost(
    String postId, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'social/post/get', 'postId': postId},
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> toggleLike(
    String postId,
    String userId,
    bool isLike, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'social/post/like',
      'postId': postId,
      'userId': userId,
      'isLike': isLike,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> addView(
    String postId, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'social/post/view', 'postId': postId},
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> addComment(
    String postId,
    String userId,
    String text, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'social/comment/add',
      'postId': postId,
      'userId': userId,
      'text': text,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> getComments(
    String postId, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'social/comment/get', 'postId': postId},
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> toggleCommentLike(
    String commentId,
    String userId,
    bool isLike, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'social/comment/like',
      'commentId': commentId,
      'userId': userId,
      'isLike': isLike,
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

  Future<RevaniResponse> getList(
    String userId, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'chat/get-list',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'userId': userId,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> delete(
    String chatId, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'chat/delete', 'chatId': chatId},
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> sendMessage(
    String chatId,
    String senderId,
    Map<String, dynamic> messageData, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'chat/message/send',
      'chatId': chatId,
      'senderId': senderId,
      'messageData': messageData,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> listMessages(
    String chatId, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'chat/message/list', 'chatId': chatId},
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> updateMessage(
    String messageId,
    String senderId,
    String newText, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'chat/message/update',
      'messageId': messageId,
      'senderId': senderId,
      'newText': newText,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> deleteMessage(
    String messageId,
    String userId, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'chat/message/delete', 'messageId': messageId, 'userId': userId},
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> react(
    String messageId,
    String userId,
    String emoji,
    bool add, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'chat/message/react',
      'messageId': messageId,
      'userId': userId,
      'emoji': emoji,
      'add': add,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> pin(
    String messageId,
    bool pin, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'chat/message/pin', 'messageId': messageId, 'pin': pin},
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> getPinned(
    String chatId, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'chat/message/get-pinned', 'chatId': chatId},
    onSuccess: onSuccess,
    onError: onError,
  );
}

class RevaniLivekit {
  final RevaniClient _client;
  RevaniLivekit(this._client);

  Future<RevaniResponse> init(
    String host,
    String apiKey,
    String apiSecret, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'livekit/init',
      'host': host,
      'apiKey': apiKey,
      'apiSecret': apiSecret,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> connect({
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'livekit/connect',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> createToken({
    required String roomName,
    required String userID,
    required String userName,
    bool isAdmin = false,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'livekit/create-token',
      'roomName': roomName,
      'userID': userID,
      'userName': userName,
      'isAdmin': isAdmin,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> createRoom(
    String roomName, {
    int timeout = 10,
    int maxUsers = 50,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'livekit/create-room',
      'roomName': roomName,
      'emptyTimeoutMinute': timeout,
      'maxUsers': maxUsers,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> closeRoom(
    String roomName, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'livekit/close-room', 'roomName': roomName},
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> getRoomInfo(
    String roomName, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'livekit/get-room-info', 'roomName': roomName},
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> getAllRooms({
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'livekit/get-all-rooms'},
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> kickUser(
    String roomName,
    String userID, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'livekit/kick-user', 'roomName': roomName, 'userID': userID},
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> getUserInfo(
    String roomName,
    String userID, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'livekit/get-user-info', 'roomName': roomName, 'userID': userID},
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> updateMetadata(
    String roomName,
    String metadata, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'livekit/update-metadata',
      'roomName': roomName,
      'metadata': metadata,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> updateParticipant(
    String roomName,
    String userID, {
    String? metadata,
    dynamic permission,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'livekit/update-participant',
      'roomName': roomName,
      'userID': userID,
      'metadata': metadata,
      'permission': permission,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> muteParticipant(
    String roomName,
    String userID,
    String trackSid,
    bool muted, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'livekit/mute-participant',
      'roomName': roomName,
      'userID': userID,
      'trackSid': trackSid,
      'muted': muted,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> listParticipants(
    String roomName, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'livekit/list-participants', 'roomName': roomName},
    onSuccess: onSuccess,
    onError: onError,
  );
}

class RevaniPubSub {
  final RevaniClient _client;
  RevaniPubSub(this._client);

  Future<RevaniResponse> subscribe(
    String topic,
    String clientId, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'pubsub/subscribe',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'clientId': clientId,
      'topic': topic,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> publish(
    String topic,
    Map<String, dynamic> data, {
    String? clientId,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'pubsub/publish',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'topic': topic,
      'data': data,
      'clientId': clientId,
    },
    onSuccess: onSuccess,
    onError: onError,
  );

  Future<RevaniResponse> unsubscribe(
    String topic,
    String clientId, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {'cmd': 'pubsub/unsubscribe', 'clientId': clientId, 'topic': topic},
    onSuccess: onSuccess,
    onError: onError,
  );
}

class RevaniStorage {
  final RevaniClient _client;

  RevaniStorage(this._client);

  Future<RevaniResponse> upload({
    required File file,
    String? fileName,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) async {
    try {
      if (!file.existsSync()) {
        final res = RevaniResponse(
          status: 404,
          message: "File not found locally",
          error: "FileSystemException",
        );
        onError?.call(res);
        return res;
      }

      final stream = file.openRead();
      final length = await file.length();
      final name = fileName ?? p.basename(file.path);

      final url = Uri.parse("${_client.httpBaseUrl}/upload");
      final request = http.StreamedRequest("POST", url);

      request.headers['x-account-id'] = _client.accountID;
      request.headers['x-project-name'] = _client.projectName;
      request.headers['x-session-token'] = _client.token;
      request.headers['x-file-name'] = name;
      request.headers['content-type'] = 'application/octet-stream';
      request.contentLength = length;

      stream.listen(
        (chunk) => request.sink.add(chunk),
        onDone: () => request.sink.close(),
        onError: (e) {
          request.sink.addError(e);
          request.sink.close();
        },
        cancelOnError: true,
      );

      final streamedResponse = await request.send();
      final responseString = await streamedResponse.stream.bytesToString();
      final jsonResponse = jsonDecode(responseString);
      final res = RevaniResponse.fromMap(jsonResponse);

      if (res.isSuccess) {
        onSuccess?.call(res);
      } else {
        onError?.call(res);
      }
      return res;
    } catch (e) {
      final res = RevaniResponse.networkError(e.toString());
      onError?.call(res);
      return res;
    }
  }

  Future<void> downloadToFile({
    required String projectID,
    required String fileId,
    required String savePath,
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) async {
    try {
      final url = Uri.parse("${_client.httpBaseUrl}/file/$projectID/$fileId");

      final request = http.Request('GET', url);
      final response = await _client._httpClient.send(request);

      if (response.statusCode == 200) {
        final file = File(savePath);
        final sink = file.openWrite();

        await response.stream.pipe(sink);
        await sink.flush();
        await sink.close();

        final res = RevaniResponse(
          status: 200,
          message: "File downloaded to $savePath",
          data: {"path": savePath},
        );
        onSuccess?.call(res);
      } else {
        final res = RevaniResponse(
          status: response.statusCode,
          message: "Download Failed",
          error: response.reasonPhrase,
        );
        onError?.call(res);
      }
    } catch (e) {
      final res = RevaniResponse.networkError(e.toString());
      onError?.call(res);
    }
  }

  Future<RevaniResponse> delete(
    String fileId, {
    SuccessCallback? onSuccess,
    ErrorCallback? onError,
  }) => _client.execute(
    {
      'cmd': 'storage/delete',
      'accountID': _client.accountID,
      'projectName': _client.projectName,
      'fileId': fileId,
    },
    onSuccess: onSuccess,
    onError: onError,
  );
}
