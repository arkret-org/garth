//! Real HTTPS fixtures with an explicit test-owned CA and no global TLS changes.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

struct NativeTls {
    server: Arc<rustls::ServerConfig>,
    roots: Vec<reqwest::Certificate>,
}

static TLS: OnceLock<NativeTls> = OnceLock::new();

pub(crate) fn server_config() -> Arc<rustls::ServerConfig> {
    TLS.get_or_init(NativeTls::new).server.clone()
}

pub(crate) fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .tls_backend_rustls()
        .tls_certs_only(TLS.get_or_init(NativeTls::new).roots.clone())
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .expect("build the explicit-CA native HTTPS test client")
}

impl NativeTls {
    fn new() -> Self {
        let supplied = (
            std::env::var_os("COTEST_RUN_SCOPED_CA_PEM"),
            std::env::var_os("COLAND_TLS_CERT_PATH"),
            std::env::var_os("COLAND_TLS_KEY_PATH"),
        );
        let (ca, cert, key, _directory) = match supplied {
            (Some(ca), Some(cert), Some(key)) => (
                PathBuf::from(ca),
                PathBuf::from(cert),
                PathBuf::from(key),
                None,
            ),
            (None, None, None) => {
                let directory =
                    tempfile::tempdir().expect("create the native TLS fixture directory");
                let (ca, cert, key) = generate_credentials(directory.path());
                (ca, cert, key, Some(directory))
            }
            _ => panic!(
                "supply all three native TLS paths (COTEST_RUN_SCOPED_CA_PEM, COLAND_TLS_CERT_PATH, COLAND_TLS_KEY_PATH), or none for self-contained OpenSSL credentials"
            ),
        };
        let roots = reqwest::Certificate::from_pem_bundle(
            &std::fs::read(ca).expect("read the native test CA"),
        )
        .expect("parse the native test CA");
        assert!(!roots.is_empty(), "the native test CA bundle is empty");
        let certificates = CertificateDer::pem_file_iter(cert)
            .expect("read the native test server chain")
            .collect::<Result<Vec<_>, _>>()
            .expect("parse the native test server chain");
        let key = PrivateKeyDer::from_pem_file(key).expect("parse the native test server key");
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("select safe TLS protocols")
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .expect("bind the native test server certificate and key");
        // The generated files can now be removed. Both transports own the parsed material.
        Self {
            server: Arc::new(server),
            roots,
        }
    }
}

fn openssl(directory: &Path, arguments: &[&str]) {
    let output = Command::new("openssl")
        .current_dir(directory)
        .args(arguments)
        .output()
        .expect("OpenSSL is required for self-contained native HTTPS tests; install it on PATH or supply the three official native TLS paths");
    assert!(
        output.status.success(),
        "OpenSSL native test credential generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn generate_credentials(directory: &Path) -> (PathBuf, PathBuf, PathBuf) {
    std::fs::write(
        directory.join("ca.cnf"),
        "[req]\ndistinguished_name=dn\nx509_extensions=ca_extensions\nprompt=no\n[dn]\nCN=Garth ephemeral test CA\n[ca_extensions]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n",
    )
    .expect("write the native TLS CA constraints");
    std::fs::write(
        directory.join("server.ext"),
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n",
    )
    .expect("write the native TLS server constraints");
    openssl(
        directory,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "2",
            "-subj",
            "/CN=Garth ephemeral test CA",
            "-config",
            "ca.cnf",
            "-keyout",
            "ca-key.pem",
            "-out",
            "ca.pem",
        ],
    );
    openssl(
        directory,
        &[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-config",
            "ca.cnf",
            "-subj",
            "/CN=Garth ephemeral test server",
            "-keyout",
            "server-key.pem",
            "-out",
            "server.csr",
        ],
    );
    openssl(
        directory,
        &[
            "x509",
            "-req",
            "-in",
            "server.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca-key.pem",
            "-CAcreateserial",
            "-sha256",
            "-days",
            "2",
            "-extfile",
            "server.ext",
            "-out",
            "server.pem",
        ],
    );
    openssl(
        directory,
        &[
            "verify",
            "-CAfile",
            "ca.pem",
            "-purpose",
            "sslserver",
            "server.pem",
        ],
    );
    let mut chain =
        std::fs::read(directory.join("server.pem")).expect("read the generated TLS leaf");
    chain.extend(std::fs::read(directory.join("ca.pem")).expect("read the generated TLS CA"));
    std::fs::write(directory.join("server-chain.pem"), chain).expect("write the native TLS chain");
    (
        directory.join("ca.pem"),
        directory.join("server-chain.pem"),
        directory.join("server-key.pem"),
    )
}
