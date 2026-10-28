import { useState, useEffect } from "react";
import "./App.css";

const API_URL = "http://127.0.0.1:5000";

function App() {
  const [isLogin, setIsLogin] = useState(true);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);

  const [token, setToken] = useState(
    localStorage.getItem("cipherVaultToken") || ""
  );

  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("cipherVaultUser")) || null;
    } catch {
      return null;
    }
  });

  const [files, setFiles] = useState([]);
  const [sharedFiles, setSharedFiles] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [logs, setLogs] = useState([]);
  const [activeTab, setActiveTab] = useState("my-files");
  const [selectedFile, setSelectedFile] = useState(null);
  const [shareEmail, setShareEmail] = useState("");
  const [shareFileId, setShareFileId] = useState("");
  const [dashboardMessage, setDashboardMessage] = useState("");

  useEffect(() => {
    if (token && user) {
      loadDashboardData(token);
    }
  }, [token, user]);

  async function handleAuth(event) {
    event.preventDefault();
    setMessage("");
    setLoading(true);

    const endpoint = isLogin ? "login" : "register";

    const payload = isLogin
      ? { email, password }
      : { name, email, password };

    try {
      const response = await fetch(
        `${API_URL}/api/auth/${endpoint}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error || data.message || "Authentication failed."
        );
      }

      if (isLogin) {
        localStorage.setItem("cipherVaultToken", data.token);
        localStorage.setItem("cipherVaultUser", JSON.stringify(data.user));

        setToken(data.token);
        setUser(data.user);
        setMessage("");
      } else {
        setMessage("Registration successful! You can now sign in.");
        setIsLogin(true);
        setPassword("");
      }
    } catch (error) {
      setMessage(
        error.message || "Unable to connect to the server."
      );
    } finally {
      setLoading(false);
    }
  }

  async function apiRequest(path, options = {}, authToken = token) {
    const response = await fetch(`${API_URL}${path}`, {
      ...options,
      headers: {
        ...(options.body instanceof FormData
          ? {}
          : options.body
            ? { "Content-Type": "application/json" }
            : {}),
        Authorization: `Bearer ${authToken}`,
        ...options.headers,
      },
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        data.error || data.message || "Request failed."
      );
    }

    return data;
  }

  async function loadDashboardData(authToken = token) {
    setDashboardMessage("Loading your secure workspace...");

    const results = await Promise.allSettled([
      apiRequest("/api/files/my", {}, authToken),
      apiRequest("/api/files/shared-with-me", {}, authToken),
      apiRequest("/api/security/alerts", {}, authToken),
      apiRequest("/api/security/logs", {}, authToken),
    ]);

    if (results[0].status === "fulfilled") {
      setFiles(results[0].value.files || []);
    }

    if (results[1].status === "fulfilled") {
      setSharedFiles(results[1].value.files || []);
    }

    if (results[2].status === "fulfilled") {
      setAlerts(results[2].value.alerts || []);
    }

    if (results[3].status === "fulfilled") {
      setLogs(results[3].value.logs || []);
    }

    const failures = results.filter(
      (result) => result.status === "rejected"
    );

    setDashboardMessage(
      failures.length === 0
        ? "Your secure workspace is ready."
        : "Dashboard loaded. Some sections could not be retrieved."
    );
  }

  async function uploadFile(event) {
    event.preventDefault();

    if (!selectedFile) {
      setDashboardMessage("Choose a file before uploading.");
      return;
    }

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const data = await apiRequest("/api/files/upload", {
        method: "POST",
        body: formData,
      });

      setDashboardMessage(
        data.message || "File encrypted and uploaded successfully."
      );

      setSelectedFile(null);
      event.target.reset();

      await loadDashboardData();
      setActiveTab("my-files");
    } catch (error) {
      setDashboardMessage(error.message);
    }
  }

  async function downloadFile(fileId, filename) {
    try {
      const response = await fetch(
        `${API_URL}/api/files/download/${fileId}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!response.ok) {
        let errorMessage = "Download failed.";

        try {
          const data = await response.json();
          errorMessage = data.error || errorMessage;
        } catch {
          // Keep the default error message if the response is not JSON.
        }

        throw new Error(errorMessage);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");

      link.href = url;
      link.download = filename || "downloaded-file";

      document.body.appendChild(link);
      link.click();
      link.remove();

      window.URL.revokeObjectURL(url);

      setDashboardMessage(
        "File decrypted and downloaded successfully."
      );
    } catch (error) {
      setDashboardMessage(error.message);
    }
  }

  async function shareFile(event) {
    event.preventDefault();

    if (!shareFileId) {
      setDashboardMessage("Please select a file to share.");
      return;
    }

    if (!shareEmail.trim()) {
      setDashboardMessage("Please enter the recipient's email.");
      return;
    }

    try {
      const data = await apiRequest("/api/files/share", {
        method: "POST",
        body: JSON.stringify({
          file_id: shareFileId,
          email: shareEmail.trim(),
        }),
      });

      setDashboardMessage(
        data.message || "File shared successfully."
      );

      setShareEmail("");
      setShareFileId("");
      setActiveTab("my-files");

      await loadDashboardData();
    } catch (error) {
      setDashboardMessage(error.message);
    }
  }

  function openShareForm(file) {
    setShareFileId(file.id);
    setShareEmail("");
    setDashboardMessage("");
    setActiveTab("share");
  }

  function logout() {
    localStorage.removeItem("cipherVaultToken");
    localStorage.removeItem("cipherVaultUser");

    setToken("");
    setUser(null);
    setFiles([]);
    setSharedFiles([]);
    setAlerts([]);
    setLogs([]);
    setMessage("");
    setDashboardMessage("");
    setEmail("");
    setPassword("");
    setName("");
    setSelectedFile(null);
    setShareEmail("");
    setShareFileId("");
    setActiveTab("my-files");
  }

  if (token && user) {
    const fileToShare = files.find(
      (file) => file.id === shareFileId
    );

    return (
      <div className="dashboard-layout">
        <aside className="sidebar">
          <div className="brand">
            <span className="brand-icon">⬡</span>
            <span>CipherVault</span>
          </div>

          <p className="sidebar-caption">SECURE WORKSPACE</p>

          <button
            className={
              activeTab === "my-files"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setActiveTab("my-files")}
          >
            My Files
          </button>

          <button
            className={
              activeTab === "upload"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setActiveTab("upload")}
          >
            Upload File
          </button>

          <button
            className={
              activeTab === "shared"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setActiveTab("shared")}
          >
            Shared With Me
          </button>

          <button
            className={
              activeTab === "alerts"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setActiveTab("alerts")}
          >
            Security Alerts
          </button>

          <button
            className={
              activeTab === "logs"
                ? "nav-item active"
                : "nav-item"
            }
            onClick={() => setActiveTab("logs")}
          >
            Security Logs
          </button>

          <div className="sidebar-bottom">
            <div className="user-badge">
              <div className="avatar">
                {(user.name || user.email || "U")
                  .charAt(0)
                  .toUpperCase()}
              </div>

              <div className="user-details">
                <strong>
                  {user.name || "CipherVault User"}
                </strong>
                <span>{user.email}</span>
              </div>
            </div>

            <button
              className="logout-button"
              onClick={logout}
            >
              Sign out
            </button>
          </div>
        </aside>

        <main className="dashboard-main">
          <header className="topbar">
            <div>
              <p className="eyebrow">
                CIPHER VAULT / WORKSPACE
              </p>

              <h1>
                {activeTab === "my-files" && "My Files"}
                {activeTab === "upload" && "Secure File Upload"}
                {activeTab === "shared" && "Shared With Me"}
                {activeTab === "share" && "Share File"}
                {activeTab === "alerts" && "Security Alerts"}
                {activeTab === "logs" && "Security Logs"}
              </h1>
            </div>

            <div className="secure-indicator">
              <span className="status-dot" />
              Authenticated
            </div>
          </header>

          <div className="welcome-banner">
            <div>
              <p className="eyebrow">
                YOUR PRIVATE WORKSPACE
              </p>

              <h2>
                Welcome back, {user.name || user.email}.
              </h2>

              <p>
                Protect, manage, and share your files securely.
              </p>
            </div>

            <div className="banner-symbol">⬡</div>
          </div>

          <section className="stats-grid">
            <div className="stat-card">
              <span className="stat-label">MY FILES</span>
              <strong>{files.length}</strong>
              <span className="stat-note">Encrypted uploads</span>
            </div>

            <div className="stat-card">
              <span className="stat-label">SHARED FILES</span>
              <strong>{sharedFiles.length}</strong>
              <span className="stat-note">
                Files shared with you
              </span>
            </div>

            <div className="stat-card">
              <span className="stat-label">SECURITY ALERTS</span>
              <strong>{alerts.length}</strong>
              <span className="stat-note">Detected alerts</span>
            </div>

            <div className="stat-card">
              <span className="stat-label">CRYPTOGRAPHY</span>
              <strong className="crypto-value">AES-256</strong>
              <span className="stat-note">
                GCM authenticated encryption
              </span>
            </div>
          </section>

          {dashboardMessage && (
            <div
              className="dashboard-message"
              role="status"
            >
              {dashboardMessage}
            </div>
          )}

          <section className="content-panel">
            {activeTab === "my-files" && (
              <>
                <div className="section-heading">
                  <div>
                    <h2>Your encrypted files</h2>
                    <p>
                      Files you have uploaded to CipherVault.
                    </p>
                  </div>

                  <button
                    className="primary-button"
                    onClick={() => setActiveTab("upload")}
                  >
                    + Upload file
                  </button>
                </div>

                {files.length === 0 ? (
                  <div className="empty-state">
                    <div className="empty-icon">▤</div>
                    <h3>No files yet</h3>
                    <p>
                      Upload your first file to begin protecting
                      your data.
                    </p>
                  </div>
                ) : (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>FILE NAME</th>
                          <th>SIZE</th>
                          <th>STATUS</th>
                          <th>ACTION</th>
                          <th>SHARE</th>
                        </tr>
                      </thead>

                      <tbody>
                        {files.map((file) => (
                          <tr key={file.id}>
                            <td>{file.filename}</td>

                            <td>
                              {(
                                (file.size_bytes || 0) / 1024
                              ).toFixed(1)}{" "}
                              KB
                            </td>

                            <td>
                              <span className="file-status">
                                {file.status || "encrypted"}
                              </span>
                            </td>

                            <td>
                              <button
                                className="text-button"
                                onClick={() =>
                                  downloadFile(
                                    file.id,
                                    file.filename
                                  )
                                }
                              >
                                Download
                              </button>
                            </td>

                            <td>
                              <button
                                className="text-button"
                                onClick={() =>
                                  openShareForm(file)
                                }
                              >
                                Share
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}

            {activeTab === "upload" && (
              <div className="form-section">
                <h2>Encrypt and upload a file</h2>

                <p>
                  Your file will be encrypted by the backend
                  before it is stored. Maximum file size: 10 MB.
                </p>

                <form
                  onSubmit={uploadFile}
                  className="upload-form"
                >
                  <label htmlFor="secure-file">
                    Choose a file
                  </label>

                  <input
                    id="secure-file"
                    type="file"
                    onChange={(event) =>
                      setSelectedFile(
                        event.target.files?.[0] || null
                      )
                    }
                  />

                  {selectedFile && (
                    <p className="selected-file">
                      Selected: {selectedFile.name}
                    </p>
                  )}

                  <button
                    className="primary-button"
                    type="submit"
                  >
                    Encrypt &amp; upload
                  </button>
                </form>
              </div>
            )}

            {activeTab === "shared" && (
              <>
                <div className="section-heading">
                  <div>
                    <h2>Files shared with you</h2>
                    <p>
                      Download files another registered user
                      shared with you.
                    </p>
                  </div>
                </div>

                {sharedFiles.length === 0 ? (
                  <div className="empty-state">
                    <div className="empty-icon">⇄</div>
                    <h3>No shared files</h3>
                    <p>
                      Files shared with your account will appear
                      here.
                    </p>
                  </div>
                ) : (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>FILE NAME</th>
                          <th>SIZE</th>
                          <th>STATUS</th>
                          <th>ACTION</th>
                        </tr>
                      </thead>

                      <tbody>
                        {sharedFiles.map((file) => (
                          <tr key={file.id}>
                            <td>{file.filename}</td>

                            <td>
                              {(
                                (file.size_bytes || 0) / 1024
                              ).toFixed(1)}{" "}
                              KB
                            </td>

                            <td>
                              <span className="file-status">
                                {file.status || "encrypted"}
                              </span>
                            </td>

                            <td>
                              <button
                                className="text-button"
                                onClick={() =>
                                  downloadFile(
                                    file.id,
                                    file.filename
                                  )
                                }
                              >
                                Download
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}

            {activeTab === "share" && (
              <div className="form-section">
                <h2>Share an encrypted file</h2>

                <p>
                  Share access with another registered
                  CipherVault user by email.
                </p>

                <div className="selected-file">
                  <strong>Selected file:</strong>{" "}
                  {fileToShare
                    ? fileToShare.filename
                    : "No file selected"}

                  {fileToShare && (
                    <div style={{ marginTop: "12px" }}>
                      <strong>File ID</strong>

                      <div
                        style={{
                          display: "flex",
                          gap: "8px",
                          alignItems: "center",
                          flexWrap: "wrap",
                          marginTop: "6px",
                        }}
                      >
                        <code
                          style={{
                            overflowWrap: "anywhere",
                          }}
                        >
                          {fileToShare.id}
                        </code>

                        <button
                          type="button"
                          className="secondary-button"
                          onClick={async () => {
                            try {
                              await navigator.clipboard.writeText(
                                fileToShare.id
                              );
                              setDashboardMessage(
                                "File ID copied to clipboard."
                              );
                            } catch {
                              setDashboardMessage(
                                "Unable to copy the ID. Select and copy it manually."
                              );
                            }
                          }}
                        >
                          Copy ID
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                <form
                  onSubmit={shareFile}
                  className="upload-form"
                >
                  <label htmlFor="recipient-email">
                    Recipient email
                  </label>

                  <input
                    id="recipient-email"
                    type="email"
                    value={shareEmail}
                    onChange={(event) =>
                      setShareEmail(event.target.value)
                    }
                    placeholder="sharetest@example.com"
                    required
                  />

                  <button
                    className="primary-button"
                    type="submit"
                    disabled={!fileToShare}
                  >
                    Share file
                  </button>

                  <button
                    type="button"
                    className="secondary-button"
                    onClick={() => {
                      setShareFileId("");
                      setShareEmail("");
                      setActiveTab("my-files");
                    }}
                  >
                    Cancel
                  </button>
                </form>
              </div>
            )}

            {activeTab === "alerts" && (
              <>
                <div className="section-heading">
                  <div>
                    <h2>Threat detection</h2>
                    <p>
                      Alerts returned by the backend security
                      monitor.
                    </p>
                  </div>

                  <button
                    className="secondary-button"
                    onClick={() => loadDashboardData()}
                  >
                    Refresh
                  </button>
                </div>

                {alerts.length === 0 ? (
                  <div className="empty-state">
                    <div className="empty-icon">✓</div>
                    <h3>No active alerts returned</h3>
                    <p>
                      The backend did not report any alerts
                      for your account during its current
                      detection window.
                    </p>
                  </div>
                ) : (
                  <div className="list-stack">
                    {alerts.map((alert, index) => (
                      <div
                        className="alert-card"
                        key={`${alert.type}-${index}`}
                      >
                        <span className="alert-severity">
                          {alert.severity || "NOTICE"}
                        </span>

                        <div>
                          <h3>
                            {alert.type || "Security alert"}
                          </h3>
                          <p>{alert.message}</p>

                          {alert.count != null && (
                            <small>
                              Related events: {alert.count}
                            </small>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}

            {activeTab === "logs" && (
              <>
                <div className="section-heading">
                  <div>
                    <h2>Security activity</h2>
                    <p>
                      Recent security events recorded for
                      your account.
                    </p>
                  </div>

                  <button
                    className="secondary-button"
                    onClick={() => loadDashboardData()}
                  >
                    Refresh
                  </button>
                </div>

                {logs.length === 0 ? (
                  <div className="empty-state">
                    <div className="empty-icon">≡</div>
                    <h3>No security logs returned</h3>
                    <p>
                      Activity recorded for your account
                      will appear here.
                    </p>
                  </div>
                ) : (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>EVENT</th>
                          <th>DETAILS</th>
                          <th>TIME</th>
                        </tr>
                      </thead>

                      <tbody>
                        {logs.map((log, index) => (
                          <tr
                            key={
                              log.id ||
                              `${log.event}-${index}`
                            }
                          >
                            <td>
                              {log.event ||
                                log.action ||
                                "Security event"}
                            </td>

                            <td>
                              {log.details ||
                                log.description ||
                                "—"}
                            </td>

                            <td>
                              {log.timestamp
                                ? new Date(
                                    log.timestamp
                                  ).toLocaleString()
                                : log.created_at
                                  ? new Date(
                                      log.created_at
                                    ).toLocaleString()
                                  : "—"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </section>

          <footer className="dashboard-footer">
            CipherVault · Secure File Sharing and Threat Detection
          </footer>
        </main>
      </div>
    );
  }

  return (
    <main className="auth-page">
      <section className="auth-visual">
        <div className="auth-brand">
          <span className="brand-icon">⬡</span>
          <span>CipherVault</span>
        </div>

        <div className="visual-content">
          <span className="pill">
            <span className="status-dot" />
            SECURITY-FIRST FILE SHARING
          </span>

          <h1>
            Your files.
            <br />
            Your privacy.
            <br />
            <span>Protected.</span>
          </h1>

          <p>
            A secure workspace powered by hybrid cryptography,
            authenticated encryption, and intelligent threat
            detection.
          </p>

          <div className="security-features">
            <div>
              <span className="feature-icon">◇</span>
              <div>
                <strong>AES-256-GCM</strong>
                <span>Authenticated file encryption</span>
              </div>
            </div>

            <div>
              <span className="feature-icon">⌘</span>
              <div>
                <strong>RSA-OAEP</strong>
                <span>Encryption key protection</span>
              </div>
            </div>

            <div>
              <span className="feature-icon">⌁</span>
              <div>
                <strong>Threat Detection</strong>
                <span>Monitor suspicious activity</span>
              </div>
            </div>
          </div>
        </div>

        <div className="visual-footer">
          HYBRID CRYPTOGRAPHY · SECURE ACCESS · AUDIT LOGGING
        </div>
      </section>

      <section className="auth-panel">
        <div className="auth-form-container">
          <div className="mobile-brand">
            <span className="brand-icon">⬡</span>
            <span>CipherVault</span>
          </div>

          <p className="eyebrow">YOUR SECURE WORKSPACE</p>

          <h2>
            {isLogin ? "Welcome back" : "Create your account"}
          </h2>

          <p className="form-subtitle">
            {isLogin
              ? "Sign in to access your protected files."
              : "Join CipherVault to secure and share your files."}
          </p>

          <div className="auth-tabs">
            <button
              type="button"
              className={
                isLogin ? "auth-tab selected" : "auth-tab"
              }
              onClick={() => {
                setIsLogin(true);
                setMessage("");
              }}
            >
              Sign in
            </button>

            <button
              type="button"
              className={
                !isLogin ? "auth-tab selected" : "auth-tab"
              }
              onClick={() => {
                setIsLogin(false);
                setMessage("");
              }}
            >
              Create account
            </button>
          </div>

          <form
            className="auth-form"
            onSubmit={handleAuth}
          >
            {!isLogin && (
              <div className="input-group">
                <label htmlFor="name">Full name</label>

                <input
                  id="name"
                  type="text"
                  value={name}
                  onChange={(event) =>
                    setName(event.target.value)
                  }
                  placeholder="Enter your name"
                  autoComplete="name"
                  required
                />
              </div>
            )}

            <div className="input-group">
              <label htmlFor="email">Email address</label>

              <input
                id="email"
                type="email"
                value={email}
                onChange={(event) =>
                  setEmail(event.target.value)
                }
                placeholder="you@example.com"
                autoComplete="email"
                required
              />
            </div>

            <div className="input-group">
              <label htmlFor="password">Password</label>

              <input
                id="password"
                type="password"
                value={password}
                onChange={(event) =>
                  setPassword(event.target.value)
                }
                placeholder="Enter your password"
                autoComplete={
                  isLogin
                    ? "current-password"
                    : "new-password"
                }
                minLength={isLogin ? undefined : 12}
                required
              />

              {!isLogin && (
                <small className="input-hint">
                  Use at least 12 characters.
                </small>
              )}
            </div>

            {message && (
              <div
                className="auth-message"
                role="alert"
              >
                {message}
              </div>
            )}

            <button
              className="submit-button"
              type="submit"
              disabled={loading}
            >
              {loading
                ? "Please wait..."
                : isLogin
                  ? "Sign in securely →"
                  : "Create secure account →"}
            </button>
          </form>

          <p className="auth-disclaimer">
            Your credentials are protected using secure
            authentication practices.
          </p>
        </div>

        <div className="panel-footer">
          <span>© 2026 CipherVault</span>
          <span>Secure by design.</span>
        </div>
      </section>
    </main>
  );
}

export default App;