/**
 * Jest setup file for Parcela UI tests
 * 
 * This file sets up the test environment to mock Tauri's invoke API
 * and provides helpers for testing the UI logic.
 */

// Mock the Tauri API
global.mockInvokeResponses = {};

global.window = {
  __TAURI__: {
    core: {
      invoke: jest.fn((command, args) => {
        if (global.mockInvokeResponses[command]) {
          const response = global.mockInvokeResponses[command];
          if (typeof response === 'function') {
            return Promise.resolve(response(args));
          }
          return Promise.resolve(response);
        }
        return Promise.reject(new Error(`Unmocked command: ${command}`));
      }),
    },
  },
};

// Helper to set mock responses for Tauri commands
global.mockTauriCommand = (command, response) => {
  global.mockInvokeResponses[command] = response;
};

// Helper to clear all mocks
global.clearTauriMocks = () => {
  global.mockInvokeResponses = {};
  if (global.window.__TAURI__?.core?.invoke?.mockClear) {
    global.window.__TAURI__.core.invoke.mockClear();
  }
};

// Mock DOM elements that main.js expects
global.document = {
  getElementById: jest.fn((id) => {
    // Return mock elements for the IDs that main.js uses
    return {
      classList: {
        add: jest.fn(),
        remove: jest.fn(),
        contains: jest.fn(() => false),
      },
      addEventListener: jest.fn(),
      textContent: '',
      innerHTML: '',
      style: {},
      disabled: false,
      value: '',
      title: '',
      scrollIntoView: jest.fn(),
      appendChild: jest.fn(),
      querySelectorAll: jest.fn(() => []),
    };
  }),
};

// Reset mocks before each test
beforeEach(() => {
  global.clearTauriMocks();
});

