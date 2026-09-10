import { Component, ElementRef, HostListener, ViewChild } from '@angular/core';
import * as CryptoJS from 'crypto-js';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss'],
})
export class AppComponent {
  title = 'EncryptDecrypt';
  textToCopy: string = '';

  encDecKey: string = '';
  encDecKeyIV: string = '';
  userPlainText: string = '';
  userEncryptedText: string = '';

  encryptedData: string = '';
  decryptedData: string = '';

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

  // Function to copy text to the clipboard
  copyToClipboard(copiedData: string): void {
    this.textToCopy = copiedData;
    if (!this.textToCopy) {
      alert('No text to copy!');
      return;
    }
    navigator.clipboard
      .writeText(this.textToCopy)
      .then(() => {
        // alert('Text copied to clipboard!');
      })
      .catch((err) => {
        console.error('Failed to copy text: ', err);
      });
  }
}
