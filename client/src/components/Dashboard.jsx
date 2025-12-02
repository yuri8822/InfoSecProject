/**
 * Dashboard Component
 * Main application dashboard showing users, key management, and audit logs
 */

import React from 'react';
import { Shield, Key, Terminal, LogOut, CheckCircle, AlertCircle } from 'lucide-react';

export default function Dashboard({ 
  user, 
  keyStatus, 
  logs, 
  users, 
  selectedUser, 
  onLogout, 
  onRefreshLogs, 
  onRefreshUsers,
  onSelectUser,
  onFetchPublicKey
}) {
  return (
    <div className="w-full max-w-5xl space-y-6">
      <header className="flex items-center justify-between bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 bg-indigo-100 rounded-full flex items-center justify-center text-indigo-700 font-bold text-xl">
            {user.username[0].toUpperCase()}
          </div>
          <div>
            <h1 className="text-xl font-bold text-gray-900">Welcome, {user.username}</h1>
            <div className="flex items-center gap-2 text-sm text-gray-500">
              <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
              Secure Connection Established
            </div>
          </div>
        </div>
        <button 
          onClick={onLogout}
          className="flex items-center gap-2 px-4 py-2 text-gray-600 hover:bg-gray-50 rounded-lg transition-colors"
        >
          <LogOut size={18} />
          Logout
        </button>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* User Directory Panel */}
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Shield className="text-blue-500" />
              <h3 className="text-lg font-semibold text-gray-800">Registered Users</h3>
            </div>
            <button onClick={onRefreshUsers} className="text-xs text-blue-600 hover:underline">Refresh</button>
          </div>
          
          <div className="space-y-2 max-h-64 overflow-y-auto custom-scrollbar">
            {users.length === 0 ? (
              <div className="text-center text-gray-400 text-sm py-8">No other users found</div>
            ) : (
              users.map((u) => (
                <div 
                  key={u._id}
                  onClick={() => onSelectUser(u)}
                  className={`p-3 rounded-lg border cursor-pointer transition-all ${
                    selectedUser?._id === u._id 
                      ? 'bg-blue-50 border-blue-300 shadow-sm' 
                      : 'bg-gray-50 border-gray-200 hover:bg-gray-100'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 bg-gradient-to-br from-indigo-500 to-purple-500 rounded-full flex items-center justify-center text-white font-bold text-sm">
                      {u.username[0].toUpperCase()}
                    </div>
                    <div className="flex-1">
                      <div className="font-medium text-gray-800">{u.username}</div>
                      <div className="text-xs text-gray-400">
                        Joined {new Date(u.createdAt).toLocaleDateString()}
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>

          {selectedUser && (
            <div className="mt-4 p-3 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg border border-blue-200">
              <div className="text-xs font-semibold text-blue-700 mb-1">Selected User</div>
              <div className="font-medium text-gray-800">{selectedUser.username}</div>
              <button 
                onClick={() => onFetchPublicKey(selectedUser.username)}
                className="mt-2 w-full py-1.5 px-3 bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium rounded transition-colors"
              >
                Chat (E2EE)
              </button>
            </div>
          )}
        </div>

        {/* Key Management Panel */}
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <div className="flex items-center gap-2 mb-4">
            <Key className="text-amber-500" />
            <h3 className="text-lg font-semibold text-gray-800">Key Management</h3>
          </div>
          
          <div className="space-y-4">
            <div className="p-4 bg-gray-50 rounded-lg border border-gray-100">
              <div className="flex justify-between items-center mb-2">
                <span className="text-sm font-medium text-gray-600">Storage Mechanism</span>
                <span className="text-xs bg-blue-100 text-blue-700 px-2 py-1 rounded">IndexedDB</span>
              </div>
              <div className="flex justify-between items-center mb-2">
                <span className="text-sm font-medium text-gray-600">Algorithm</span>
                <span className="text-xs bg-purple-100 text-purple-700 px-2 py-1 rounded">RSA-OAEP 2048</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm font-medium text-gray-600">Private Key Status</span>
                {keyStatus === 'present' ? (
                  <span className="flex items-center gap-1 text-xs text-green-600 font-medium bg-green-50 px-2 py-1 rounded">
                    <CheckCircle size={12} /> Securely Stored
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-xs text-red-600 font-medium bg-red-50 px-2 py-1 rounded">
                    <AlertCircle size={12} /> Missing on Device
                  </span>
                )}
              </div>
            </div>
            <p className="text-xs text-gray-400">
              Your private key never leaves this device. It was generated using the Web Crypto API and is stored in a sandboxed database within your browser.
            </p>
          </div>
        </div>

        {/* Security Audit Log Panel */}
        <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 flex flex-col h-80">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Terminal className="text-slate-700" />
              <h3 className="text-lg font-semibold text-gray-800">Server-Side Audit Logs</h3>
            </div>
            <button onClick={onRefreshLogs} className="text-xs text-blue-600 hover:underline">Refresh</button>
          </div>
          
          <div className="flex-1 overflow-y-auto bg-slate-900 rounded-lg p-4 font-mono text-xs text-slate-300 space-y-2 custom-scrollbar">
            {logs.length === 0 ? (
              <div className="text-center text-slate-600 italic mt-10">No logs found</div>
            ) : (
              logs.map((log, idx) => (
                <div key={idx} className="border-b border-slate-800 pb-2 mb-2 last:border-0 last:mb-0 last:pb-0">
                  <div className="flex justify-between text-slate-500 mb-1">
                    <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
                    <span className={`uppercase font-bold ${
                      log.type.includes('FAIL') || log.type.includes('WARNING') ? 'text-red-400' : 
                      log.type.includes('KEY') ? 'text-amber-400' : 'text-green-400'
                    }`}>{log.type}</span>
                  </div>
                  <div className="text-slate-200">{log.details}</div>
                  <div className="text-slate-600 text-[10px] mt-0.5">IP: {log.ipAddress}</div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
