/**
 * PART 5: End-to-End Encrypted File Sharing Component
 * Handles file upload and download with client-side encryption
 * 
 * Security Features:
 * - Files encrypted with AES-256-GCM client-side before upload
 * - Files split into chunks for efficient processing
 * - AES key encrypted with recipient's RSA public key
 * - Server stores only encrypted chunks - cannot decrypt
 * - Decryption happens exclusively on client-side
 */

import React, { useState, useEffect } from 'react';
import {
  Upload,
  Download,
  Trash2,
  Lock,
  CheckCircle,
  AlertTriangle,
  Loader,
  FileText,
  Clock,
  User,
  Shield
} from 'lucide-react';

import {
  encryptFileForSharing,
  decryptFileFromSharing,
  generateAESKey,
  importPublicKey
} from '../utils/crypto';

import {
  uploadEncryptedFile,
  fetchSharedFiles,
  downloadEncryptedFile,
  deleteSharedFile,
  logFileSharingEvent,
  fetchUserPublicKey
} from '../utils/api';

import { getPrivateKey } from '../utils/indexedDB';

export default function FileSharing({ user }) {
  // ============ FILE UPLOAD STATE ============
  const [selectedFile, setSelectedFile] = useState(null);
  const [recipientUsername, setRecipientUsername] = useState('');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploading, setUploading] = useState(false);

  // ============ FILE LIST STATE ============
  const [sharedFiles, setSharedFiles] = useState([]);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [downloadingFileId, setDownloadingFileId] = useState(null);

  // ============ STATUS & NOTIFICATIONS ============
  const [statusMessage, setStatusMessage] = useState('');
  const [statusType, setStatusType] = useState(''); // 'success', 'error', 'info', 'loading'

  // Initialize by loading shared files
  useEffect(() => {
    loadSharedFiles();
  }, []);

  // ============ HELPER: Show status message ============
  const showStatus = (message, type = 'info', duration = 3000) => {
    setStatusMessage(message);
    setStatusType(type);
    if (duration) {
      setTimeout(() => {
        setStatusMessage('');
        setStatusType('');
      }, duration);
    }
  };

  // ============ LOAD SHARED FILES ============
  const loadSharedFiles = async () => {
    setLoadingFiles(true);
    try {
      const files = await fetchSharedFiles(user.token);
      setSharedFiles(files || []);
      showStatus(`Loaded ${files?.length || 0} shared files`, 'success', 2000);
    } catch (err) {
      console.error('Failed to load shared files:', err);
      showStatus('Failed to load shared files: ' + err.message, 'error');
    } finally {
      setLoadingFiles(false);
    }
  };

  // ============ HANDLE FILE UPLOAD ============
  const handleFileUpload = async (e) => {
    e.preventDefault();

    if (!selectedFile) {
      showStatus('Please select a file', 'error');
      return;
    }

    if (!recipientUsername) {
      showStatus('Please enter recipient username', 'error');
      return;
    }

    setUploading(true);
    setUploadProgress(0);

    try {
      // Step 1: Fetch recipient's public key
      showStatus('Fetching recipient public key...', 'loading', false);
      const recipientPubKeyJWK = await fetchUserPublicKey(recipientUsername, user.token);
      if (!recipientPubKeyJWK) {
        throw new Error('Recipient public key not found');
      }

      setUploadProgress(20);

      // Step 2: Import recipient's public key
      showStatus('Importing recipient public key...', 'loading', false);
      const recipientPublicKey = await importPublicKey(recipientPubKeyJWK);

      setUploadProgress(30);

      // Step 3: Encrypt file client-side
      showStatus('Encrypting file (AES-256-GCM) and splitting into chunks...', 'loading', false);
      const fileMetadata = await encryptFileForSharing(selectedFile, recipientPublicKey);

      setUploadProgress(60);

      // Step 4: Upload encrypted file to server
      showStatus('Uploading encrypted file to server...', 'loading', false);
      const uploadResponse = await uploadEncryptedFile(fileMetadata, recipientUsername, user.token);

      setUploadProgress(90);

      // Step 5: Log security event
      await logFileSharingEvent(
        'FILE_SHARED',
        `File "${selectedFile.name}" (${Math.round(selectedFile.size / 1024 / 1024)}MB) encrypted and shared with ${recipientUsername}`,
        user.token
      );

      setUploadProgress(100);
      showStatus(`File "${selectedFile.name}" successfully encrypted and uploaded!`, 'success', 4000);

      // Reset form
      setSelectedFile(null);
      setRecipientUsername('');
      setUploadProgress(0);

      // Refresh file list
      setTimeout(() => loadSharedFiles(), 1000);

    } catch (err) {
      console.error('File upload failed:', err);
      showStatus(`Upload failed: ${err.message}`, 'error', 5000);
      await logFileSharingEvent('FILE_UPLOAD_FAILED', `Error: ${err.message}`, user.token).catch(console.error);
    } finally {
      setUploading(false);
    }
  };

  // ============ HANDLE FILE DOWNLOAD & DECRYPT ============
  const handleFileDownload = async (file) => {
    setDownloadingFileId(file._id);

    try {
      // Step 1: Download encrypted file from server
      showStatus('Downloading encrypted file...', 'loading', false);
      const encryptedFileData = await downloadEncryptedFile(file._id, user.token);

      // Step 2: Get user's private key
      showStatus('Retrieving your private key...', 'loading', false);
      const myPrivateKey = await getPrivateKey(user.username);
      if (!myPrivateKey) {
        throw new Error('Your private key not found on this device');
      }

      // Step 3: Decrypt file client-side
      showStatus('Decrypting file (AES-256-GCM)...', 'loading', false);
      const decryptedBlob = await decryptFileFromSharing(encryptedFileData, myPrivateKey);

      // Step 4: Create download link and trigger download
      const url = URL.createObjectURL(decryptedBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = file.fileName;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      // Step 5: Log security event
      await logFileSharingEvent(
        'FILE_DOWNLOADED_DECRYPTED',
        `File "${file.fileName}" downloaded and decrypted successfully`,
        user.token
      );

      showStatus(`File "${file.fileName}" decrypted and downloaded!`, 'success', 3000);

      // Refresh file list
      setTimeout(() => loadSharedFiles(), 500);

    } catch (err) {
      console.error('File download/decryption failed:', err);
      showStatus(`Download failed: ${err.message}`, 'error', 5000);
      await logFileSharingEvent('FILE_DOWNLOAD_FAILED', `Error: ${err.message}`, user.token).catch(console.error);
    } finally {
      setDownloadingFileId(null);
    }
  };

  // ============ HANDLE FILE DELETION ============
  const handleFileDelete = async (fileId, fileName) => {
    if (!confirm(`Delete file "${fileName}"? This action cannot be undone.`)) return;

    try {
      showStatus('Deleting file...', 'loading', false);
      await deleteSharedFile(fileId, user.token);

      await logFileSharingEvent(
        'FILE_DELETED',
        `File "${fileName}" deleted by sender`,
        user.token
      );

      showStatus(`File "${fileName}" deleted successfully`, 'success', 2000);
      setSharedFiles(sharedFiles.filter(f => f._id !== fileId));

    } catch (err) {
      console.error('File deletion failed:', err);
      showStatus(`Deletion failed: ${err.message}`, 'error');
    }
  };

  // ============ FORMAT FILE SIZE ============
  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  // ============ FORMAT DATE ============
  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <div className="w-full max-w-5xl space-y-6">
      {/* STATUS MESSAGE */}
      {statusMessage && (
        <div
          className={`p-4 rounded-lg border flex items-center gap-3 ${
            statusType === 'success'
              ? 'bg-green-50 border-green-200 text-green-800'
              : statusType === 'error'
              ? 'bg-red-50 border-red-200 text-red-800'
              : statusType === 'loading'
              ? 'bg-blue-50 border-blue-200 text-blue-800'
              : 'bg-gray-50 border-gray-200 text-gray-800'
          }`}
        >
          {statusType === 'loading' ? (
            <Loader size={18} className="animate-spin" />
          ) : statusType === 'success' ? (
            <CheckCircle size={18} />
          ) : statusType === 'error' ? (
            <AlertTriangle size={18} />
          ) : (
            <Shield size={18} />
          )}
          <span className="text-sm font-medium">{statusMessage}</span>
        </div>
      )}

      {/* UPLOAD SECTION */}
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div className="flex items-center gap-2 mb-6">
          <Lock className="text-blue-500" />
          <h2 className="text-lg font-semibold text-gray-900">Securely Share Files</h2>
        </div>

        <form onSubmit={handleFileUpload} className="space-y-4">
          {/* FILE INPUT */}
          <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-blue-400 transition-colors cursor-pointer"
               onClick={() => document.getElementById('fileInput').click()}>
            <Upload size={32} className="mx-auto text-gray-400 mb-2" />
            <p className="text-sm font-medium text-gray-700">
              {selectedFile ? selectedFile.name : 'Click to select file or drag and drop'}
            </p>
            <p className="text-xs text-gray-500 mt-1">
              Any file type • Encrypted with AES-256-GCM
            </p>
            <input
              id="fileInput"
              type="file"
              hidden
              onChange={(e) => {
                if (e.target.files?.[0]) {
                  setSelectedFile(e.target.files[0]);
                  setUploadProgress(0);
                }
              }}
              disabled={uploading}
            />
          </div>

          {/* RECIPIENT INPUT */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Recipient Username
            </label>
            <input
              type="text"
              value={recipientUsername}
              onChange={(e) => setRecipientUsername(e.target.value)}
              placeholder="Enter recipient's username"
              disabled={uploading}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none disabled:bg-gray-50"
            />
          </div>

          {/* PROGRESS BAR */}
          {uploadProgress > 0 && (
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div
                className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                style={{ width: `${uploadProgress}%` }}
              ></div>
            </div>
          )}

          {/* SUBMIT BUTTON */}
          <button
            type="submit"
            disabled={uploading || !selectedFile}
            className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 text-white font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {uploading ? (
              <>
                <Loader size={18} className="animate-spin" />
                Encrypting & Uploading...
              </>
            ) : (
              <>
                <Upload size={18} />
                Encrypt & Share File
              </>
            )}
          </button>
        </form>

        <div className="mt-4 p-4 bg-blue-50 rounded-lg border border-blue-200">
          <div className="flex gap-2">
            <Shield size={16} className="text-blue-600 flex-shrink-0 mt-0.5" />
            <div className="text-sm text-blue-900">
              <p className="font-medium mb-1">🔐 End-to-End Encryption</p>
              <ul className="space-y-1 text-xs list-disc list-inside">
                <li>File encrypted <strong>before</strong> upload with AES-256-GCM</li>
                <li>Split into chunks for efficient processing</li>
                <li>AES key encrypted with recipient's RSA-2048 public key</li>
                <li>Server stores only encrypted data</li>
                <li>Only recipient can decrypt using their private key</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* SHARED FILES SECTION */}
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2">
            <Download className="text-green-500" />
            <h2 className="text-lg font-semibold text-gray-900">Files Shared With You</h2>
          </div>
          <button
            onClick={loadSharedFiles}
            disabled={loadingFiles}
            className="text-xs text-blue-600 hover:underline disabled:text-gray-400"
          >
            {loadingFiles ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>

        {loadingFiles ? (
          <div className="flex items-center justify-center py-8">
            <Loader size={24} className="animate-spin text-gray-400" />
          </div>
        ) : sharedFiles.length === 0 ? (
          <div className="text-center py-12">
            <FileText size={32} className="mx-auto text-gray-300 mb-2" />
            <p className="text-gray-500">No files shared with you yet</p>
          </div>
        ) : (
          <div className="space-y-3">
            {sharedFiles.map((file) => (
              <div
                key={file._id}
                className="p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <Lock size={16} className="text-gray-400" />
                      <p className="font-medium text-gray-900">{file.fileName}</p>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs text-gray-600">
                      <div className="flex items-center gap-1">
                        <FileText size={14} />
                        {formatFileSize(file.fileSize)}
                      </div>
                      <div className="flex items-center gap-1">
                        <User size={14} />
                        From {file.from}
                      </div>
                      <div className="flex items-center gap-1">
                        <Clock size={14} />
                        {formatDate(file.uploadedAt)}
                      </div>
                      <div className="flex items-center gap-1">
                        <Shield size={14} />
                        {file.totalChunks} chunks
                      </div>
                    </div>
                    {file.isDownloaded && (
                      <div className="mt-2 text-xs text-green-600 flex items-center gap-1">
                        <CheckCircle size={12} />
                        Downloaded
                      </div>
                    )}
                  </div>

                  {/* DOWNLOAD BUTTON */}
                  <button
                    onClick={() => handleFileDownload(file)}
                    disabled={downloadingFileId === file._id}
                    className="ml-4 px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-300 text-white text-sm font-medium rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap"
                  >
                    {downloadingFileId === file._id ? (
                      <>
                        <Loader size={14} className="animate-spin" />
                        Decrypting...
                      </>
                    ) : (
                      <>
                        <Download size={14} />
                        Download
                      </>
                    )}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* SECURITY INFO */}
      <div className="bg-gradient-to-r from-green-50 to-emerald-50 p-6 rounded-xl border border-green-200">
        <div className="flex gap-3">
          <Shield className="text-green-600 flex-shrink-0" />
          <div>
            <h3 className="font-semibold text-green-900 mb-2">How File Encryption Works</h3>
            <ol className="text-sm text-green-800 space-y-1 list-decimal list-inside">
              <li><strong>Upload:</strong> Your file is encrypted AES-256-GCM on your device with a unique key</li>
              <li><strong>Chunk:</strong> Encrypted file is split into 5MB chunks for efficiency</li>
              <li><strong>Key Sharing:</strong> AES key is encrypted with recipient's RSA-2048 public key</li>
              <li><strong>Storage:</strong> Server stores encrypted chunks - we cannot access your data</li>
              <li><strong>Download:</strong> Recipient's device decrypts the AES key, then decrypts all chunks</li>
              <li><strong>Privacy:</strong> Only sender and recipient can access the file</li>
            </ol>
          </div>
        </div>
      </div>
    </div>
  );
}
