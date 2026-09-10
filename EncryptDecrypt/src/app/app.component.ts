import { Component, ElementRef, HostListener, ViewChild } from '@angular/core';
import * as CryptoJS from 'crypto-js';
import { RsaCryptoService } from './services/rsa-crypto.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss'],
})
export class AppComponent {
  title = 'EncryptDecrypt';
  textToCopy: string = '';

  // Id of the copy icon currently showing the "copied" tick, if any.
  copiedId: string | null = null;

  constructor(private rsaCrypto: RsaCryptoService) {}

  // Active screen: 'aes' or 'rsa'
  activeMode: 'aes' | 'rsa' = 'aes';

  encDecKey: string = '';
  encDecKeyIV: string = '';
  userPlainText: string = '';
  userEncryptedText: string = '';

  encryptedData: string = '';
  decryptedData: string = '';

  // RSA specific fields
  rsaPublicKey: string = '';
  rsaPrivateKey: string = '';
  rsaUserPlainText: string = '';
  rsaUserEncryptedText: string = '';
  rsaEncryptedData: string = '';
  rsaDecryptedData: string = '';
  rsaError: string = '';

  setMode(mode: 'aes' | 'rsa') {
    this.activeMode = mode;
  }

  clearAll() {
    this.encDecKey = '';
    this.encDecKeyIV = '';
    this.clearEncryptDataFields();
    this.clearDecryptDataFields();
  }

  clearEncryptDataFields() {
    this.userPlainText = '';
    this.encryptedData = '';
  }

  clearDecryptDataFields() {
    this.userEncryptedText = '';
    this.decryptedData = '';
  }

  dataEncryptor(plainTextData: any) {
    if (plainTextData && this.encDecKey && this.encDecKeyIV) {
      const key = CryptoJS.enc.Hex.parse(this.encDecKey);
      const iv = CryptoJS.enc.Hex.parse(this.encDecKeyIV);
      const encrypted = CryptoJS.AES.encrypt(plainTextData.toString(), key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });
      this.encryptedData = encrypted.toString();
      return encrypted.toString();
    }
    return null;
  }

  dataDecryptor(encryptedData: any) {
    if (encryptedData && this.encDecKey) {
      const key = CryptoJS.enc.Hex.parse(this.encDecKey);
      const iv = CryptoJS.enc.Hex.parse(this.encDecKeyIV);
      const decrypted = CryptoJS.AES.decrypt(encryptedData.toString(), key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });
      this.decryptedData = decrypted.toString(CryptoJS.enc.Utf8);
      return decrypted.toString(CryptoJS.enc.Utf8);
    }
    return null;
  }

  // Function to copy text to the clipboard.
  // `id` (optional) identifies which copy icon triggered this, so it can
  // briefly swap to a tick icon and revert after 2 seconds.
  copyToClipboard(copiedData: string, id?: string): void {
    this.textToCopy = copiedData;
    if (!this.textToCopy) {
      alert('No text to copy!');
      return;
    }
    navigator.clipboard
      .writeText(this.textToCopy)
      .then(() => {
        if (id) {
          this.copiedId = id;
          setTimeout(() => {
            if (this.copiedId === id) {
              this.copiedId = null;
            }
          }, 2000);
        }
      })
      .catch((err) => {
        console.error('Failed to copy text: ', err);
      });
  }

  // ---------------- RSA Section ----------------
  // RSA-OAEP / SHA-256 via RsaCryptoService (node-forge), which is
  // equivalent to .NET's RSA.Create() + RSAEncryptionPadding.OaepSHA256
  // used in the reference C# implementation. See RsaCryptoService for why
  // node-forge is used instead of the browser's crypto.subtle.

  clearRsaEncryptDataFields() {
    this.rsaUserPlainText = '';
    this.rsaEncryptedData = '';
    this.rsaError = '';
  }

  clearRsaDecryptDataFields() {
    this.rsaUserEncryptedText = '';
    this.rsaDecryptedData = '';
    this.rsaError = '';
  }

  clearRsaAll() {
    this.rsaPublicKey = '';
    this.rsaPrivateKey = '';
    this.clearRsaEncryptDataFields();
    this.clearRsaDecryptDataFields();
  }

  async rsaDataEncryptor(plainTextData: any) {
    this.rsaError = '';
    if (!plainTextData || !this.rsaPublicKey) {
      return null;
    }
    try {
      this.rsaEncryptedData = await this.rsaCrypto.encrypt(
        plainTextData.toString(),
        this.rsaPublicKey
      );
      return this.rsaEncryptedData;
    } catch (err: any) {
      console.error('RSA encryption failed: ', err);
      this.rsaError = err?.message || 'RSA encryption failed. Please check the public key and try again.';
      return null;
    }
  }

  async rsaDataDecryptor(encryptedData: any) {
    this.rsaError = '';
    if (!encryptedData || !this.rsaPrivateKey) {
      return null;
    }
    try {
      this.rsaDecryptedData = await this.rsaCrypto.decrypt(
        encryptedData.toString(),
        this.rsaPrivateKey
      );
      return this.rsaDecryptedData;
    } catch (err: any) {
      console.error('RSA decryption failed: ', err);
      this.rsaError = err?.message || 'RSA decryption failed. Please check the private key and encrypted text.';
      return null;
    }
  }
}
