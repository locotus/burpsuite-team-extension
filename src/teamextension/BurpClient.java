package teamextension;

import burp.ICookie;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.framing.CloseFrame;
import org.java_websocket.handshake.ServerHandshake;

import javax.net.ssl.*;
import javax.swing.*;
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Type;
import java.net.ConnectException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

class BurpClient {

    private static final String TAG = "[BTCP]";
    private static final String SERVER = "server";
    private final String username;
    private String serverAddress;
    private WebSocketClient cc;
    private SharedValues sharedValues;
    private ArrayList<String> mutedClients;
    private String currentRoom = SERVER;
    private boolean paused;

    private void log(String message) {
        sharedValues.getCallbacks().printOutput(TAG + " " + message);
    }

    private void logError(String message) {
        sharedValues.getCallbacks().printError(TAG + " " + message);
    }

    BurpClient(String serverAddress,
               final String serverPassword,
               final String username,
               SharedValues sharedValues) throws URISyntaxException {
        this.username = username;
        mutedClients = new ArrayList<>();
        this.paused = false;
        this.serverAddress = serverAddress;
        this.sharedValues = sharedValues;

        log("========================================");
        log("BurpClient initializing...");
        log("Server address: " + serverAddress);
        log("Username: " + username);
        log("Current room: " + currentRoom);
        log("========================================");

        HashMap<String, String> authHeaders = new HashMap<>();
        authHeaders.put("Auth", serverPassword);
        authHeaders.put("Username", username);
        log("Auth headers prepared: Auth=<password>, Username=" + username);

        log("Creating WebSocket connection to: wss://" + serverAddress);
        cc = new WebSocketClient(new URI("wss://" + serverAddress),
                authHeaders) {

            @Override
            public void onMessage(String message) {
                log("RECV raw message length: " + message.length() + " bytes");
                try {
                    String decodedJson = new String(
                            sharedValues.getCallbacks().getHelpers().base64Decode(message));
                    log("RECV decoded JSON: " + truncateForLog(decodedJson, 500));

                    BurpTCMessage burpTCMessage =
                            sharedValues.getGson().fromJson(decodedJson, BurpTCMessage.class);
                    log("RECV message type: " + burpTCMessage.getMessageType());
                    log("RECV data: " + truncateForLog(burpTCMessage.getData(), 200));
                    if (burpTCMessage.getRequestResponse() != null) {
                        log("RECV has request/response attached");
                    }
                    parseBurpTCMessage(burpTCMessage);
                } catch (JsonSyntaxException e) {
                    logError("JSON parse error: " + e.getMessage());
                    e.printStackTrace(new PrintStream(sharedValues.getCallbacks().getStderr()));
                } catch (Exception e) {
                    logError("Error processing message: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                    e.printStackTrace(new PrintStream(sharedValues.getCallbacks().getStderr()));
                }
            }

            @Override
            public void onOpen(ServerHandshake handshake) {
                log("========================================");
                log("WebSocket CONNECTED");
                log("URI: " + getURI());
                log("Server handshake HTTP status: " + handshake.getHttpStatus());
                log("========================================");
                sharedValues.getBurpPanel().writeToAlertPane("Connected to server: " + getURI());
                log("Requesting config from server...");
                getConfigMessage();
                log("Requesting room list from server...");
                getRoomsMessage();
                log("Connection setup complete");
            }

            @Override
            public void onClose(int code, String reason, boolean remote) {
                log("========================================");
                log("WebSocket CLOSED");
                log("Close code: " + code + " (" + getCloseCodeName(code) + ")");
                log("Reason: " + (reason != null ? reason : "none"));
                log("Remote close: " + remote);
                log("========================================");
                resetMutedClients();
                if (code == CloseFrame.ABNORMAL_CLOSE) {
                    logError("Abnormal close - connection failure");
                    sharedValues.serverConnectionFailure(1);
                } else if (code != CloseFrame.NORMAL) {
                    if (reason != null && reason.contains("401")) {
                        logError("Authentication failed (401)");
                        sharedValues.serverConnectionFailure(401);
                    } else if (reason != null && reason.contains("409")) {
                        logError("Username conflict (409)");
                        sharedValues.serverConnectionFailure(409);
                    } else {
                        logError("Connection closed with error code: " + code);
                    }
                }
                log("Muted clients list cleared");
            }

            @Override
            public void onError(Exception ex) {
                logError("========================================");
                logError("WebSocket ERROR");
                logError("Exception type: " + ex.getClass().getName());
                logError("Exception message: " + ex.getMessage());
                if (ex.getCause() != null) {
                    logError("Cause: " + ex.getCause().getMessage());
                }
                logError("========================================");
                StringWriter sw = new StringWriter();
                ex.printStackTrace(new PrintWriter(sw));
                logError("Stack trace: " + sw.toString());
                if (ex instanceof SSLException) {
                    logError("SSL error detected - error code: -4");
                    logError("Possible causes: certificate mismatch, expired cert, trust issue");
                    sharedValues.serverConnectionFailure(-4);
                } else if (ex instanceof ConnectException) {
                    logError("Connection refused - error code: -5");
                    logError("Possible causes: server not running, wrong port, firewall blocking");
                    sharedValues.serverConnectionFailure(-5);
                } else if (ex instanceof URISyntaxException) {
                    logError("Invalid URI - error code: -2");
                    sharedValues.serverConnectionFailure(-2);
                }
            }
        };

        log("Setting up SSL context...");
        log("Cert file: " + sharedValues.getCertFile());
        log("Key file: " + sharedValues.getCertKeyFile());

        if (sharedValues.getCertFile() == null) {
            logError("Cert file is NULL!");
            throw new IllegalArgumentException("Cert file not set");
        }
        if (!sharedValues.getCertFile().exists()) {
            logError("Cert file does not exist: " + sharedValues.getCertFile().getAbsolutePath());
            throw new IllegalArgumentException("Cert file not found");
        }
        if (!sharedValues.getCertFile().canRead()) {
            logError("Cert file is not readable: " + sharedValues.getCertFile().getAbsolutePath());
            throw new IllegalArgumentException("Cert file not readable");
        }

        if (sharedValues.getCertKeyFile() == null) {
            logError("Cert KEY file is NULL!");
            throw new IllegalArgumentException("Cert key file not set");
        }
        if (!sharedValues.getCertKeyFile().exists()) {
            logError("Cert KEY file does not exist: " + sharedValues.getCertKeyFile().getAbsolutePath());
            throw new IllegalArgumentException("Cert key file not found");
        }
        if (!sharedValues.getCertKeyFile().canRead()) {
            logError("Cert KEY file is not readable: " + sharedValues.getCertKeyFile().getAbsolutePath());
            throw new IllegalArgumentException("Cert key file not readable");
        }

        SSLContext sslContext = getSSLContextFromLetsEncrypt();
        SSLSocketFactory factory = sslContext.getSocketFactory();
        log("SSL socket factory created");
        cc.setSocketFactory(factory);
        log("Initiating WebSocket connection...");
        cc.connect();
        log("Connection request sent, waiting for response...");
    }

    private String truncateForLog(String str, int maxLen) {
        if (str == null) return "null";
        if (str.length() <= maxLen) return str;
        return str.substring(0, maxLen) + "... [truncated, total=" + str.length() + "]";
    }

    private String getCloseCodeName(int code) {
        switch (code) {
            case CloseFrame.NORMAL: return "NORMAL";
            case CloseFrame.GOING_AWAY: return "GOING_AWAY";
            case CloseFrame.PROTOCOL_ERROR: return "PROTOCOL_ERROR";
            case CloseFrame.UNEXPECTED_CONDITION: return "UNEXPECTED_CONDITION";
            case CloseFrame.ABNORMAL_CLOSE: return "ABNORMAL_CLOSE";
            default: return "UNKNOWN(" + code + ")";
        }
    }

    private void parseBurpTCMessage(BurpTCMessage burpTCMessage) {
        log("Processing message type: " + burpTCMessage.getMessageType());
        switch (burpTCMessage.getMessageType()) {
            case COOKIE_MESSAGE:
                log("COOKIE_MESSAGE received");
                if (burpTCMessage.getData() != null) {
                    log("Cookie data length: " + burpTCMessage.getData().length() + " chars");
                }
                if (this.sharedValues.getBurpPanel().getReceiveSharedCookiesSetting()) {
                    log("Cookie sharing enabled - applying " + (burpTCMessage.getData() != null ? "received" : "no") + " cookies");
                    List<ICookie> newCookies = this.sharedValues.getGson().fromJson(burpTCMessage.getData(), SharedValues.cookieJsonListType);
                    log("Parsed " + newCookies.size() + " cookies from message");
                    for (ICookie newCookie : newCookies) {
                        this.sharedValues.getCallbacks().updateCookieJar(newCookie);
                    }
                    log("Cookie jar updated successfully");
                } else {
                    log("Cookie sharing disabled - ignoring COOKIE_MESSAGE");
                }
                break;
            case SCAN_ISSUE_MESSAGE:
                log("SCAN_ISSUE_MESSAGE received");
                log("Issue data length: " + (burpTCMessage.getData() != null ? burpTCMessage.getData().length() : 0) + " chars");
                ScanIssue decodedIssue = this.sharedValues.getGson().fromJson(burpTCMessage.getData(), ScanIssue.class);
                log("Parsed scan issue: " + (decodedIssue != null ? decodedIssue.getIssueName() : "null"));
                decodedIssue.setRemediation();
                if (this.sharedValues.getBurpPanel().getReceiveSharedIssuesSetting()) {
                    log("Issue sharing enabled - adding scan issue to Burp");
                    this.sharedValues.getCallbacks().addScanIssue(decodedIssue);
                    log("Scan issue added successfully");
                } else {
                    log("Issue sharing disabled - ignoring SCAN_ISSUE_MESSAGE");
                }
                break;
            case GET_SCOPE_MESSAGE:
                log("GET_SCOPE_MESSAGE received");
                log("Scope data length: " + (burpTCMessage.getData() != null ? burpTCMessage.getData().length() : 0) + " chars");
                if (burpTCMessage.getData() != null && !burpTCMessage.getData().isEmpty()) {
                    try {
                        log("Loading scope configuration...");
                        this.sharedValues.getCallbacks().loadConfigFromJson(burpTCMessage.getData());
                        log("Scope configuration loaded successfully");
                    } catch (Exception e) {
                        logError("Failed to load scope: " + e.getMessage());
                    }
                } else {
                    log("No scope data in message");
                }
                break;
            case BURP_MESSAGE:
                log("BURP_MESSAGE received");
                log("Adding request/response to site map...");
                this.sharedValues.getCallbacks().addToSiteMap(burpTCMessage.getRequestResponse());
                log("Site map updated");
                break;
            case REPEATER_MESSAGE:
                log("REPEATER_MESSAGE received");
                if (burpTCMessage.getRequestResponse() != null) {
                    log("Sending to Repeater: " +
                            burpTCMessage.getRequestResponse().getHttpService().getHost() + ":" +
                            burpTCMessage.getRequestResponse().getHttpService().getPort() +
                            " (" + burpTCMessage.getRequestResponse().getHttpService().getProtocol() + ")");
                    this.sharedValues.getCallbacks().sendToRepeater(
                            burpTCMessage.getRequestResponse().getHttpService().getHost(),
                            burpTCMessage.getRequestResponse().getHttpService().getPort(),
                            burpTCMessage.getRequestResponse().getHttpService().getProtocol()
                                    .equalsIgnoreCase("https"),
                            burpTCMessage.getRequestResponse().getRequest(),
                            "BurpTC Payload");
                    log("Sent to Repeater successfully");
                } else {
                    logError("REPEATER_MESSAGE has no request/response attached!");
                }
                break;
            case INTRUDER_MESSAGE:
                log("INTRUDER_MESSAGE received");
                if (burpTCMessage.getRequestResponse() != null) {
                    log("Sending to Intruder: " +
                            burpTCMessage.getRequestResponse().getHttpService().getHost() + ":" +
                            burpTCMessage.getRequestResponse().getHttpService().getPort() +
                            " (" + burpTCMessage.getRequestResponse().getHttpService().getProtocol() + ")");
                    this.sharedValues.getCallbacks().sendToIntruder(
                            burpTCMessage.getRequestResponse().getHttpService().getHost(),
                            burpTCMessage.getRequestResponse().getHttpService().getPort(),
                            burpTCMessage.getRequestResponse().getHttpService().getProtocol()
                                    .equalsIgnoreCase("https"),
                            burpTCMessage.getRequestResponse().getRequest());
                    log("Sent to Intruder successfully");
                } else {
                    logError("INTRUDER_MESSAGE has no request/response attached!");
                }
                break;
            case NEW_MEMBER_MESSAGE:
                log("NEW_MEMBER_MESSAGE received");
                log("Room: " + this.currentRoom);
                log("Member data: " + burpTCMessage.getData());
                if (!SERVER.equals(this.currentRoom)) {
                    String[] members = burpTCMessage.getData().split(",");
                    log("Updating member list: " + members.length + " members");
                    this.sharedValues.getRoomMembersListModel().removeAllElements();
                    for (String member : members) {
                        log("  - " + member);
                        this.sharedValues.getRoomMembersListModel().addElement(member);
                    }
                    if (members.length == 1) {
                        log("Single member detected - enabling room controls");
                        this.sharedValues.getBurpPanel().enableRoomControl();
                    }
                    this.sharedValues.getBurpPanel().getRoomsPanel().repaint();
                    log("Member list updated");
                } else {
                    log("Currently on default server room - not updating member list");
                }
                break;
            case GET_ROOMS_MESSAGE:
                log("GET_ROOMS_MESSAGE received");
                String roomData = burpTCMessage.getData();
                if (roomData != null && roomData.length() > 0) {
                    String[] rooms = roomData.split(",");
                    log("Room list received: " + rooms.length + " rooms");
                    this.sharedValues.getServerListModel().removeAllElements();
                    for (String room : rooms) {
                        String[] roomValues = room.split("::");
                        String roomName = roomValues[0];
                        boolean hasPassword = roomValues.length > 1 && Boolean.parseBoolean(roomValues[1]);
                        log("  - " + roomName + " (password protected: " + hasPassword + ")");
                        this.sharedValues.getServerListModel().addElement(new Room(roomName, hasPassword));
                    }
                    log("Room list updated in UI");
                } else {
                    log("No rooms available");
                    this.sharedValues.getServerListModel().removeAllElements();
                }
                break;
            case COMMENT_MESSAGE:
                log("COMMENT_MESSAGE received");
                log("Comment data hash: " + burpTCMessage.getData());
                if (burpTCMessage.getRequestResponse() != null) {
                    log("Updating request comment model...");
                    this.sharedValues.getRequestCommentModel().updateOrAddRequestResponse(burpTCMessage.getRequestResponse());
                    log("Comment model updated");
                } else {
                    logError("COMMENT_MESSAGE has no request/response attached!");
                }
                break;
            case GET_COMMENTS_MESSAGE:
                log("GET_COMMENTS_MESSAGE received");
                log("Comments data length: " + (burpTCMessage.getData() != null ? burpTCMessage.getData().length() : 0) + " chars");
                Type listType = new TypeToken<ArrayList<HttpRequestResponse>>() {}.getType();
                List<HttpRequestResponse> httpRequestResponses =
                        sharedValues.getGson().fromJson(burpTCMessage.getData(), listType);
                log("Received " + (httpRequestResponses != null ? httpRequestResponses.size() : 0) + " comments");
                if (httpRequestResponses != null) {
                    for (HttpRequestResponse requestResponse : httpRequestResponses) {
                        log("Processing comment for: " + requestResponse.getHttpService().getHost());
                        this.sharedValues.getRequestCommentModel().updateOrAddRequestResponse(requestResponse);
                    }
                }
                log("Comments processed");
                break;
            case BAD_PASSWORD_MESSAGE:
                log("BAD_PASSWORD_MESSAGE received");
                log("Room password authentication failed");
                this.sharedValues.getBurpPanel().writeToAlertPane("Bad Room Password.");
                break;
            case GOOD_PASSWORD_MESSAGE:
                log("GOOD_PASSWORD_MESSAGE received");
                log("Room password authentication successful");
                log("Joining room: " + this.currentRoom);
                this.sharedValues.getBurpPanel().joinRoom();
                break;
            case GET_CONFIG_MESSAGE:
                log("GET_CONFIG_MESSAGE received");
                String shortenerApiKey = burpTCMessage.getData();
                if (shortenerApiKey != null && shortenerApiKey.length() > 0) {
                    log("Shortener API key received: " + truncateForLog(shortenerApiKey, 20) + "...");
                    sharedValues.setUrlShortenerApiKey(shortenerApiKey);
                    log("Shortener API key configured");
                } else {
                    log("No shortener API key configured (empty)");
                }
                break;
            case ROOM_EXISTS_MESSAGE:
                log("ROOM_EXISTS_MESSAGE received");
                log("Room creation failed - room already exists");
                JOptionPane.showMessageDialog(this.sharedValues.getBurpPanel(), "The room name you submit already exists.");
                sharedValues.getBurpPanel().swapServerAndRoomLists(false);
                sharedValues.getBurpPanel().muteAllButton.setEnabled(false);
                sharedValues.getBurpPanel().setScopeButton.setEnabled(false);
                sharedValues.getBurpPanel().newRoom.setEnabled(true);
                sharedValues.getBurpPanel().leaveRoom.setEnabled(false);
                sharedValues.getBurpPanel().pauseButton.setEnabled(false);
                log("UI updated to reflect room creation failure");
                break;
            default:
                logError("Unknown message type: " + burpTCMessage.getMessageType());
                this.sharedValues.getCallbacks().printOutput("Bad msg type: " + burpTCMessage.getMessageType());
        }
        log("Message handling complete: " + burpTCMessage.getMessageType());
    }


    void muteMember(String selectedValue) {
        log("muteMember called for: " + selectedValue);
        BurpTCMessage muteMessage = new BurpTCMessage(null, MessageType.MUTE_MESSAGE, selectedValue);
        this.sendMessage(muteMessage);
        this.addMutedClient(selectedValue);
        log("Member muted locally: " + selectedValue);
    }

    void unmuteMember(String selectedValue) {
        log("unmuteMember called for: " + selectedValue);
        BurpTCMessage unmuteMessage = new BurpTCMessage(null, MessageType.UNMUTE_MESSAGE, selectedValue);
        this.sendMessage(unmuteMessage);
        this.removeMutedClient(selectedValue);
        log("Member unmuted locally: " + selectedValue);
    }

    void createRoom(String roomName, String roomPassword) {
        log("========================================");
        log("createRoom called");
        log("Room name: " + roomName);
        log("Password provided: " + (roomPassword != null && !roomPassword.isEmpty()));
        log("========================================");
        String data = roomName + ":" + (roomPassword != null ? roomPassword : "");
        BurpTCMessage newRoomMessage = new BurpTCMessage(null, MessageType.ADD_ROOM_MESSAGE, data);
        this.currentRoom = roomName;
        log("Current room set to: " + roomName);
        this.sendMessage(newRoomMessage);
        log("ADD_ROOM_MESSAGE sent");
    }

    void leaveRoom() {
        log("========================================");
        log("leaveRoom called");
        log("Current room: " + this.currentRoom);
        log("========================================");
        BurpTCMessage newRoomMessage;
        newRoomMessage = new BurpTCMessage(null, MessageType.LEAVE_ROOM_MESSAGE, null);
        this.sendMessage(newRoomMessage);
        this.currentRoom = SERVER;
        log("Returned to default room: " + SERVER);
    }

    void joinRoom(String roomName) {
        log("========================================");
        log("joinRoom called");
        log("Room name: " + roomName);
        log("========================================");
        BurpTCMessage newRoomMessage = new BurpTCMessage(null, MessageType.JOIN_ROOM_MESSAGE, roomName);
        this.currentRoom = roomName;
        log("Current room set to: " + roomName);
        this.sendMessage(newRoomMessage);
        this.sharedValues.getBurpPanel().joinRoom();
        log("JOIN_ROOM_MESSAGE sent");
    }


    void joinRoomWithPassword(String roomName, String roomPassword) {
        log("========================================");
        log("joinRoomWithPassword called");
        log("Room name: " + roomName);
        log("Password provided: " + (roomPassword != null && !roomPassword.isEmpty()));
        log("========================================");
        String data = roomName + ":" + roomPassword;
        BurpTCMessage newRoomMessage = new BurpTCMessage(null, MessageType.JOIN_ROOM_MESSAGE, data);
        this.currentRoom = roomName;
        log("Current room set to: " + roomName);
        this.sendMessage(newRoomMessage);
        log("JOIN_ROOM_MESSAGE with password sent");
    }

    private void getConfigMessage() {
        log("getConfigMessage - preparing GET_CONFIG_MESSAGE");
        BurpTCMessage getConfigMessage = new BurpTCMessage(null, MessageType.GET_CONFIG_MESSAGE, null);
        log("GET_CONFIG_MESSAGE created");
        this.sendMessage(getConfigMessage);
        log("GET_CONFIG_MESSAGE sent");
    }


    private void getRoomsMessage() {
        log("getRoomsMessage - preparing GET_ROOMS_MESSAGE");
        BurpTCMessage getRoomsMessage = new BurpTCMessage(null, MessageType.GET_ROOMS_MESSAGE, null);
        log("GET_ROOMS_MESSAGE created");
        this.sendMessage(getRoomsMessage);
        log("GET_ROOMS_MESSAGE sent");
    }

    void setRoomScope() {
        log("========================================");
        log("setRoomScope called");
        log("Current room: " + this.currentRoom);
        String scopeData = this.sharedValues.getCurrentScope();
        log("Scope data length: " + (scopeData != null ? scopeData.length() : 0) + " chars");
        log("========================================");
        BurpTCMessage setScopeMessage = new BurpTCMessage(null, MessageType.SET_SCOPE_MESSAGE, scopeData);
        log("SET_SCOPE_MESSAGE created with scope JSON");
        this.sendMessage(setScopeMessage);
        log("SET_SCOPE_MESSAGE sent");
    }

    void getRoomScope() {
        log("getRoomScope called for room: " + this.currentRoom);
        BurpTCMessage getScopeMessage = new BurpTCMessage(null, MessageType.GET_SCOPE_MESSAGE, null);
        log("GET_SCOPE_MESSAGE created");
        this.sendMessage(getScopeMessage);
        log("GET_SCOPE_MESSAGE sent");
    }

    void muteAllMembers() {
        log("muteAllMembers called");
        BurpTCMessage muteMessage = new BurpTCMessage(null, MessageType.MUTE_MESSAGE, "All");
        this.sendMessage(muteMessage);
        log("MUTE_MESSAGE sent with target=All");
    }

    void unmuteAllMembers() {
        log("unmuteAllMembers called");
        BurpTCMessage muteMessage = new BurpTCMessage(null, MessageType.UNMUTE_MESSAGE, "All");
        this.sendMessage(muteMessage);
        log("UNMUTE_MESSAGE sent with target=All");
    }

    void sendMessage(BurpTCMessage burpTCMessage) {
        log("========================================");
        log("sendMessage called");
        log("Message type: " + burpTCMessage.getMessageType());
        log("Current room: " + this.currentRoom);
        log("Paused state: " + this.paused);
        log("========================================");
        new SwingWorker<Boolean, Void>() {
            @Override
            public Boolean doInBackground() {
                if (!isPaused()) {
                    String json = sharedValues.getGson().toJson(burpTCMessage);
                    String message = sharedValues.getCallbacks().getHelpers().base64Encode(json);
                    log("SEND message type: " + burpTCMessage.getMessageType());
                    log("SEND JSON length: " + json.length() + " chars");
                    log("SEND base64 length: " + message.length() + " chars");
                    log("SEND data preview: " + truncateForLog(burpTCMessage.getData(), 100));
                    if (burpTCMessage.getRequestResponse() != null) {
                        log("SEND has request/response attached");
                    }
                    cc.send(message);
                    log("SEND complete");
                } else {
                    log("SEND skipped - communication paused");
                }
                return Boolean.TRUE;
            }

            @Override
            public void done() {
                //no cleanup needed
            }
        }.execute();
    }

    void sendCommentMessage(HttpRequestResponse requestResponseWithComments) {
        log("sendCommentMessage called");
        log("Request hash: " + requestResponseWithComments.hashCode());
        log("Host: " + requestResponseWithComments.getHttpService().getHost());
        BurpTCMessage commentMessage =
                new BurpTCMessage(requestResponseWithComments,
                        MessageType.COMMENT_MESSAGE, Integer.toString(requestResponseWithComments.hashCode()));
        log("COMMENT_MESSAGE created");
        this.sendMessage(commentMessage);
        log("COMMENT_MESSAGE sent");
    }

    private SSLContext getSSLContextFromLetsEncrypt() {
        log("getSSLContextFromLetsEncrypt called");
        SSLContext context;
        try {
            context = SSLContext.getInstance("TLS");
            log("SSL context instance created: TLS");

            String certPath = sharedValues.getCertFile().getAbsolutePath();
            String keyPath = sharedValues.getCertKeyFile().getAbsolutePath();
            log("Loading certificate from: " + certPath);

            byte[] certBytes;
            byte[] keyBytes;
            X509Certificate cert;
            RSAPrivateKey key;

            try {
                certBytes = parseDERFromPEM(Files.readAllBytes(sharedValues.getCertFile().toPath()),
                        "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
                log("Certificate loaded: " + certBytes.length + " bytes");
            } catch (Exception e) {
                logError("Failed to load certificate: " + e.getMessage());
                throw new IllegalArgumentException("Certificate load failed", e);
            }

            log("Loading key from: " + keyPath);
            try {
                keyBytes = parseDERFromPEM(Files.readAllBytes(sharedValues.getCertKeyFile().toPath()),
                        "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
                log("Key loaded: " + keyBytes.length + " bytes");
            } catch (Exception e) {
                logError("Failed to load key: " + e.getMessage());
                throw new IllegalArgumentException("Key load failed", e);
            }

            log("Generating X509Certificate...");
            try {
                cert = generateCertificateFromDER(certBytes);
            } catch (Exception e) {
                logError("Failed to generate X509Certificate: " + e.getMessage());
                throw new IllegalArgumentException("Certificate generation failed", e);
            }
            log("Certificate subject: " + cert.getSubjectX500Principal().getName());
            log("Certificate issuer: " + cert.getIssuerX500Principal().getName());

            log("Generating RSAPrivateKey...");
            try {
                key = generatePrivateKeyFromDER(keyBytes);
            } catch (Exception e) {
                logError("Failed to generate RSAPrivateKey: " + e.getMessage());
                throw new IllegalArgumentException("Key generation failed", e);
            }
            log("Private key generated successfully");

            log("Creating KeyStore...");
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            try {
                keystore.load(null, null);
            } catch (Exception e) {
                logError("Failed to initialize KeyStore: " + e.getMessage());
                throw new IllegalArgumentException("KeyStore init failed", e);
            }
            try {
                keystore.setCertificateEntry("cert-alias", cert);
                keystore.setKeyEntry("key-alias", key, new char[]{}, new Certificate[]{cert});
            } catch (Exception e) {
                logError("Failed to populate KeyStore: " + e.getMessage());
                throw new IllegalArgumentException("KeyStore population failed", e);
            }
            log("KeyStore populated with cert and key");

            log("Initializing TrustManagerFactory...");
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keystore);
            log("TrustManagerFactory initialized - will trust only our server cert");

            log("Initializing KeyManagerFactory...");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keystore, new char[]{});
            log("KeyManagerFactory initialized - will present client cert");

            KeyManager[] km = kmf.getKeyManagers();
            log("KeyManagers ready for mTLS client auth");

            log("Initializing SSLContext with mTLS...");
            context.init(km, trustManagerFactory.getTrustManagers(), null);
            log("SSLContext initialized successfully - mTLS configured");
        } catch (Exception e) {
            logError("SSL setup failed: " + e.getClass().getName() + ": " + e.getMessage());
            throw new IllegalArgumentException("SSL setup failed", e);
        }
        return context;
    }

    private byte[] parseDERFromPEM(byte[] pem, String beginDelimiter, String endDelimiter) {
        String data = new String(pem);
        log("PEM data length: " + data.length() + " chars");
        log("Looking for: " + beginDelimiter);

        int startIdx = data.indexOf(beginDelimiter);
        int endIdx = data.indexOf(endDelimiter);

        log("Begin index: " + startIdx + ", End index: " + endIdx);

        if (startIdx < 0 || endIdx < 0) {
            logError("Could not find PEM delimiters in file");
            throw new IllegalArgumentException("PEM delimiter not found");
        }

        String base64Content = data.substring(startIdx + beginDelimiter.length(), endIdx).trim();
        log("Base64 content length: " + base64Content.length() + " chars");

        byte[] derBytes = DatatypeConverter.parseBase64Binary(base64Content);
        log("DER bytes extracted: " + derBytes.length + " bytes");
        return derBytes;
    }

    private RSAPrivateKey generatePrivateKeyFromDER(byte[] keyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) factory.generatePrivate(spec);
    }

    private static X509Certificate generateCertificateFromDER(byte[] certBytes) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
    }

    boolean isConnected() {
        boolean connected = cc.isOpen();
        log("isConnected check: " + connected);
        return connected;
    }

    void leaveServer() {
        log("leaveServer called");
        log("Closing WebSocket connection...");
        cc.close();
        log("WebSocket connection closed");
    }

    boolean isPaused() {
        return this.paused;
    }

    void pauseCommunication() {
        log("pauseCommunication called");
        this.paused = true;
        log("Communication paused - messages will be queued");
    }

    void unpauseCommunication() {
        log("unpauseCommunication called");
        this.paused = false;
        log("Communication unpaused - queued messages will be sent");
    }

    String getUsername() {
        return username;
    }

    ArrayList<String> getMutedClients() {
        return mutedClients;
    }

    private void addMutedClient(String client) {
        log("addMutedClient: " + client);
        mutedClients.add(client);
        log("Muted clients now: " + mutedClients.size());
    }

    private void removeMutedClient(String client) {
        log("removeMutedClient: " + client);
        mutedClients.remove(client);
        log("Muted clients now: " + mutedClients.size());
    }

    private void resetMutedClients() {
        log("resetMutedClients called");
        int count = mutedClients.size();
        mutedClients.clear();
        log("Cleared " + count + " muted clients");
    }

    String getServerAddress() {
        return serverAddress;
    }
}
