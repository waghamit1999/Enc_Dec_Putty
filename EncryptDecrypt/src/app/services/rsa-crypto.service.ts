import { Injectable } from '@angular/core';
import { asn1, md, pki, util } from 'node-forge';

/**
 * RSA-OAEP-SHA256 encrypt/decrypt, backed by node-forge.
 *
 * Modelled on the CIEM app's crypto service
 * (ciem_v13/src/app/shared/services/crypto/crypto.service.ts), which uses
 * node-forge rather than the browser's `crypto.subtle` for RSA:
 * `crypto.subtle` only exists in a secure context (HTTPS, or localhost).
 * This tool can be opened over plain HTTP on an internal host, where
 * `crypto.subtle` is `undefined` and RSA would silently stop working after
 * deployment even though it worked on a developer machine. forge is pure
 * JavaScript, so it behaves identically over HTTP and HTTPS.
 *
 * `encrypt`/`decrypt` still return Promises even though forge is
 * synchronous under the hood, so a future swap to WebCrypto (if every
 * environment this tool runs in ever gains TLS) would not require touching
 * any caller.
 *
 * Accepts keys as raw Base64 DER — the same SubjectPublicKeyInfo /
 * PKCS8 encoding .NET's `ExportSubjectPublicKeyInfo()` /
 * `ExportPkcs8PrivateKey()` produce — or a full PEM block with
 * `-----BEGIN/END-----` headers, which is stripped automatically.
 */
@Injectable({
  providedIn: 'root',
})
export class RsaCryptoService {
  /**
   * Parsed public keys, cached by their cleaned Base64 SPKI string, so
   * re-encrypting with the same pasted key does not re-parse the ASN.1 each
   * time.
   */
  private readonly publicKeyCache = new Map<string, pki.rsa.PublicKey>();

  /**
   * RSA-OAEP-SHA256 encrypt a UTF-8 string against a Base64/PEM
   * SubjectPublicKeyInfo public key. Base64 out.
   */
  async encrypt(plainText: string, publicKeyInput: string): Promise<string> {
    const key = this.importPublicKey(publicKeyInput);

    // forge works on byte strings, so the UTF-8 encoding is explicit.
    const encrypted = key.encrypt(util.encodeUtf8(plainText), 'RSA-OAEP', {
      md: md.sha256.create(),
      mgf1: { md: md.sha256.create() },
    });

    return util.encode64(encrypted);
  }

  /**
   * RSA-OAEP-SHA256 decrypt a Base64 ciphertext against a Base64/PEM
   * PKCS8 private key. UTF-8 string out.
   */
  async decrypt(base64Ciphertext: string, privateKeyInput: string): Promise<string> {
    const key = this.importPrivateKey(privateKeyInput);

    const encrypted = util.decode64(base64Ciphertext.trim());
    const decrypted = key.decrypt(encrypted, 'RSA-OAEP', {
      md: md.sha256.create(),
      mgf1: { md: md.sha256.create() },
    });

    return util.decodeUtf8(decrypted);
  }

  /**
   * Parse a Base64/PEM SubjectPublicKeyInfo key into a forge public key.
   *
   * forge has no direct SPKI-from-Base64 entry point, so the DER is decoded
   * to ASN.1 first, same as the CIEM service's `importRsaKey`.
   */
  private importPublicKey(publicKeyInput: string): pki.rsa.PublicKey {
    const base64 = this.cleanBase64(publicKeyInput);

    const cached = this.publicKeyCache.get(base64);
    if (cached) {
      return cached;
    }

    let key: pki.rsa.PublicKey;
    try {
      const der = util.decode64(base64);
      key = pki.publicKeyFromAsn1(asn1.fromDer(der)) as pki.rsa.PublicKey;
    } catch {
      throw new Error(
        'The RSA public key could not be parsed. It must be Base64 (or PEM) ' +
          'SubjectPublicKeyInfo (SPKI) DER.'
      );
    }

    this.publicKeyCache.set(base64, key);
    return key;
  }

  /**
   * Parse a Base64/PEM PKCS8 private key into a forge private key.
   *
   * Not cached: unlike the public key (reused for every request against one
   * backend), a pasted private key in this tool is test material that
   * should not linger longer than the single decrypt it is used for.
   */
  private importPrivateKey(privateKeyInput: string): pki.rsa.PrivateKey {
    const base64 = this.cleanBase64(privateKeyInput);

    try {
      const der = util.decode64(base64);
      return pki.privateKeyFromAsn1(asn1.fromDer(der)) as pki.rsa.PrivateKey;
    } catch {
      throw new Error(
        'The RSA private key could not be parsed. It must be Base64 (or PEM) ' +
          'PKCS8 DER.'
      );
    }
  }

  /**
   * Strips PEM headers/footers and whitespace/newlines so a key can be
   * pasted either as raw Base64 DER or as a full PEM block.
   */
  private cleanBase64(pemOrBase64: string): string {
    return (pemOrBase64 || '')
      .replace(/-----BEGIN [^-]+-----/g, '')
      .replace(/-----END [^-]+-----/g, '')
      .replace(/[\r\n\s]/g, '');
  }
}
