// ==================== VIREN-/MALWARE-DATENBANK ====================
const MALWARE_SIGNATURES = {
  js: {
    cryptominers: [ /CoinHive\.Worker/, /cryptonight/, /miner\.start/, /webassembly\.instantiate.*mining/i ],
    keyloggers: [ /onkeydown.*send.*http/i, /addEventListener.*key.*XMLHttpRequest/i, /KeyLogger/i ],
    formStealers: [ /document\.forms.*submit.*send/i, /input.*value.*post/i, /FormGrabber/i ],
    ransomware: [ /crypt.*files.*decrypt/i, /AES.*encrypt.*all/i, /your.*files.*encrypted/i ],
    spyware: [ /navigator\.userAgent.*send/, /screen\.width.*post/, /localStorage.*exfiltrate/ ],
    redirectors: [ /setTimeout.*location\.href/, /window\.onload.*replace/, /iframe.*src.*malicious/ ],
    adware: [ /createElement.*script.*ads/, /document\.write.*banner/, /popunder.*window\.open/ ]
  },
  patterns: {
    obfuscated: [ /eval\(.*String\.fromCharCode/, /\\x[0-9a-f]{2}/, /unescape\(.*%/ ],
    suspiciousUrls: [ /bit\.ly.*exe/, /tinyurl.*js/, /pastebin\.com.*raw/, /github\.io.*miner/ ],
    maliciousFunctions: [ /document\.cookie.*send/, /XMLHttpRequest.*password/, /fetch.*keylog/ ]
  }
};

// ==================== HAUPT-KLASSE: COMPLETE MALWARE DEFENSE ====================
class CompleteMalwareDefense {
  constructor() {
    this.version = '2.0.0';
    this.threatsDetected = [];
    this.cleanedItems = [];
    this.quarantine = [];
    this.scanHistory = [];
    this.heuristicScore = 0;
    this.protectionActive = true;
    
    this.initializeCompleteProtection();
    console.log('🛡️  Complete Malware Defense v' + this.version + ' initialized');
  }

  // ==================== INITIALISIERUNG ====================
  initializeCompleteProtection() {
    // 1. Prevent installation
    this.blockMaliciousInstallations();
    
    // 2. Monitor in real-time
    this.startRealTimeMonitoring();
    
    // 3. Scan existing infections
    this.performFullSystemScan();
    
    // 4. Setup protective barriers
    this.setupProtectionBarriers();
    
    // 5. Auto-cleanup scheduler
    this.startAutoCleanupScheduler();
    
    // 6. User education
    this.showSecurityDashboard();
  }

  // ==================== 1. INSTALLATIONS VERHINDERN ====================
  blockMaliciousInstallations() {
    // Hook into script loading
    const originalCreateElement = document.createElement;
    document.createElement = function(tagName) {
      const element = originalCreateElement.call(document, tagName);
      
      if (tagName.toLowerCase() === 'script') {
        const originalSrc = Object.getOwnPropertyDescriptor(element, 'src');
        Object.defineProperty(element, 'src', {
          get() { return originalSrc.get.call(this); },
          set(value) {
            if (this.detectMaliciousURL(value)) {
              console.warn('🚫 Blocked malicious script:', value);
              this.logThreat('BLOCKED_INSTALL', 'Script', value);
              return; // Block setting src
            }
            originalSrc.set.call(this, value);
          }
        });
      }
      
      return element;
    };

    // Block eval-based attacks
    window.eval = new Proxy(window.eval, {
      apply(target, thisArg, args) {
        const code = args[0];
        if (this.detectObfuscatedCode(code)) {
          console.warn('🚫 Blocked malicious eval:', code.substring(0, 100));
          this.logThreat('BLOCKED_EVAL', 'Eval', code.substring(0, 200));
          return null;
        }
        return target.apply(thisArg, args);
      }
    });

    // Block Function constructor abuse
    window.Function = new Proxy(window.Function, {
      construct(target, args) {
        const code = args[args.length - 1];
        if (this.detectMaliciousPattern(code)) {
          console.warn('🚫 Blocked malicious Function constructor');
          this.logThreat('BLOCKED_FUNCTION', 'Function', code.substring(0, 200));
          return function() {};
        }
        return new target(...args);
      }
    });
  }

  // ==================== 2. ECHTZEIT-ÜBERWACHUNG ====================
  startRealTimeMonitoring() {
    // Monitor network requests
    this.monitorNetworkRequests();
    
    // Monitor DOM changes
    this.monitorDOMChanges();
    
    // Monitor storage access
    this.monitorStorageAccess();
    
    // Monitor event listeners
    this.monitorEventListeners();
    
    // Monitor WebAssembly (common for miners)
    this.monitorWebAssembly();
  }

  monitorNetworkRequests() {
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
      const [url, options] = args;
      
      // Check URL for malicious patterns
      if (this.detectMaliciousURL(url)) {
        this.logThreat('BLOCKED_FETCH', 'Network', url);
        throw new Error('Malicious request blocked');
      }
      
      // Check request body for sensitive data
      if (options && options.body) {
        const bodyStr = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
        if (this.detectDataExfiltration(bodyStr)) {
          this.logThreat('DATA_EXFILTRATION', 'Network', bodyStr.substring(0, 200));
          return new Response(null, { status: 403 });
        }
      }
      
      return originalFetch.apply(this, args);
    }.bind(this);

    // Monitor XHR requests
    const originalXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
      if (this.detectMaliciousURL(url)) {
        this.logThreat('BLOCKED_XHR', 'Network', url);
        return;
      }
      return originalXHROpen.apply(this, arguments);
    }.bind(this);
  }

  monitorDOMChanges() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === 1) { // Element node
            this.analyzeDOMElement(node);
          }
        });
      });
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['src', 'href', 'onclick', 'onload']
    });
  }

  analyzeDOMElement(element) {
    // Check scripts
    if (element.tagName === 'SCRIPT') {
      const src = element.src;
      const content = element.textContent;
      
      if (src && this.detectMaliciousURL(src)) {
        element.remove();
        this.logThreat('REMOVED_SCRIPT', 'DOM', src);
      }
      
      if (content && this.detectMaliciousCode(content)) {
        element.remove();
        this.logThreat('REMOVED_INLINE_SCRIPT', 'DOM', content.substring(0, 200));
      }
    }
    
    // Check iframes
    if (element.tagName === 'IFRAME') {
      const src = element.src;
      if (src && this.detectMaliciousURL(src)) {
        element.remove();
        this.logThreat('REMOVED_IFRAME', 'DOM', src);
      }
    }
    
    // Check event handlers
    ['onclick', 'onload', 'onerror', 'onmouseover'].forEach((event) => {
      const handler = element.getAttribute(event);
      if (handler && this.detectMaliciousCode(handler)) {
        element.removeAttribute(event);
        this.logThreat('REMOVED_EVENT_HANDLER', 'DOM', event + ': ' + handler);
      }
    });
  }

  // ==================== 3. VOLLSTÄNDIGER SYSTEM-SCAN ====================
  async performFullSystemScan() {
    console.log('🔍 Starting complete system scan...');
    
    const scanResults = {
      timestamp: new Date().toISOString(),
      scans: []
    };

    // 1. Scan all scripts
    scanResults.scans.push(await this.scanAllScripts());
    
    // 2. Scan localStorage
    scanResults.scans.push(this.scanLocalStorage());
    
    // 3. Scan sessionStorage
    scanResults.scans.push(this.scanSessionStorage());
    
    // 4. Scan cookies
    scanResults.scans.push(this.scanCookies());
    
    // 5. Scan IndexedDB
    scanResults.scans.push(await this.scanIndexedDB());
    
    // 6. Scan service workers
    scanResults.scans.push(await this.scanServiceWorkers());
    
    // 7. Scan WebRTC (data channels)
    scanResults.scans.push(this.scanWebRTC());
    
    // 8. Heuristic behavioral scan
    scanResults.scans.push(this.performHeuristicAnalysis());
    
    // Save scan results
    this.scanHistory.push(scanResults);
    
    // Perform cleanup based on results
    this.executeCleanup(scanResults);
    
    // Generate report
    this.generateScanReport(scanResults);
    
    return scanResults;
  }

  scanAllScripts() {
    const results = {
      type: 'SCRIPTS',
      threats: [],
      cleaned: []
    };

    // External scripts
    document.querySelectorAll('script[src]').forEach((script) => {
      const src = script.src;
      if (this.detectMaliciousURL(src)) {
        results.threats.push({
          type: 'MALICIOUS_SCRIPT',
          src: src,
          action: 'REMOVED'
        });
        script.remove();
        results.cleaned.push(src);
      }
    });

    // Inline scripts
    document.querySelectorAll('script:not([src])').forEach((script) => {
      const content = script.textContent;
      if (this.detectMaliciousCode(content)) {
        results.threats.push({
          type: 'INLINE_MALWARE',
          preview: content.substring(0, 100),
          action: 'REMOVED'
        });
        script.remove();
        results.cleaned.push('inline_script');
      }
    });

    return results;
  }

  scanLocalStorage() {
    const results = {
      type: 'LOCALSTORAGE',
      threats: [],
      cleaned: []
    };

    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      const value = localStorage.getItem(key);
      
      // Check for malicious data
      if (this.detectMaliciousPattern(value) || this.isSuspiciousKey(key)) {
        results.threats.push({
          type: 'MALICIOUS_STORAGE',
          key: key,
          preview: value.substring(0, 100),
          action: 'QUARANTINED'
        });
        
        // Quarantine instead of immediate deletion
        this.quarantineItem('localStorage', key, value);
        localStorage.removeItem(key);
        results.cleaned.push(key);
      }
    }

    return results;
  }

  scanSessionStorage() {
    const results = {
      type: 'SESSIONSTORAGE',
      threats: [],
      cleaned: []
    };

    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      const value = sessionStorage.getItem(key);
      
      if (this.detectMaliciousPattern(value)) {
        results.threats.push({
          type: 'MALICIOUS_SESSION',
          key: key,
          action: 'CLEARED'
        });
        sessionStorage.removeItem(key);
        results.cleaned.push(key);
      }
    }

    return results;
  }

  scanCookies() {
    const results = {
      type: 'COOKIES',
      threats: [],
      cleaned: []
    };

    document.cookie.split(';').forEach(cookie => {
      const [name, value] = cookie.trim().split('=');
      
      // Check for tracking/malicious cookies
      if (this.isSuspiciousCookie(name, value)) {
        results.threats.push({
          type: 'MALICIOUS_COOKIE',
          name: name,
          action: 'EXPIRED'
        });
        
        // Expire the cookie
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
        results.cleaned.push(name);
      }
    });

    return results;
  }

  async scanIndexedDB() {
    const results = {
      type: 'INDEXEDDB',
      threats: [],
      cleaned: []
    };

    try {
      const databases = await indexedDB.databases();
      for (const dbInfo of databases) {
        if (this.isSuspiciousDatabaseName(dbInfo.name)) {
          results.threats.push({
            type: 'SUSPICIOUS_DB',
            name: dbInfo.name,
            action: 'FLAGGED'
          });
          // Note: Actual deletion requires opening the database
        }
      }
    } catch (e) {
      console.log('IndexedDB scan not supported');
    }

    return results;
  }

  async scanServiceWorkers() {
    const results = {
      type: 'SERVICE_WORKERS',
      threats: [],
      cleaned: []
    };

    try {
      const registrations = await navigator.serviceWorker.getRegistrations();
      for (const registration of registrations) {
        const scriptURL = registration.active?.scriptURL || '';
        
        if (this.detectMaliciousURL(scriptURL)) {
          results.threats.push({
            type: 'MALICIOUS_SERVICE_WORKER',
            url: scriptURL,
            action: 'UNREGISTERED'
          });
          
          await registration.unregister();
          results.cleaned.push(scriptURL);
        }
      }
    } catch (e) {
      console.log('Service Worker scan not available');
    }

    return results;
  }

  // ==================== 4. HEURISTISCHE ANALYSE ====================
  performHeuristicAnalysis() {
    const results = {
      type: 'HEURISTIC',
      threats: [],
      score: 0
    };

    let score = 0;
    const threats = [];

    // Check CPU usage pattern (mining detection)
    if (this.detectHighCPUUsage()) {
      score += 30;
      threats.push({
        type: 'CRYPTOMINING_SUSPECTED',
        reason: 'High CPU usage pattern detected'
      });
    }

    // Check memory usage
    if (this.detectMemoryLeak()) {
      score += 20;
      threats.push({
        type: 'MEMORY_LEAK',
        reason: 'Abnormal memory growth detected'
      });
    }

    // Check network patterns
    if (this.detectSuspiciousNetworkPatterns()) {
      score += 25;
      threats.push({
        type: 'DATA_EXFILTRATION',
        reason: 'Suspicious network request pattern'
      });
    }

    // Check for hidden elements
    if (this.detectHiddenMaliciousElements()) {
      score += 15;
      threats.push({
        type: 'HIDDEN_ELEMENTS',
        reason: 'Invisible malicious elements found'
      });
    }

    // Check for obfuscation
    if (this.detectObfuscationPatterns()) {
      score += 20;
      threats.push({
        type: 'OBFUSCATED_CODE',
        reason: 'Heavily obfuscated code detected'
      });
    }

    results.score = score;
    results.threats = threats;
    this.heuristicScore = score;

    if (score > 50) {
      this.triggerHighAlert();
    }

    return results;
  }

  detectHighCPUUsage() {
    // Simple heuristic: Check for long-running tasks
    const start = performance.now();
    let count = 0;
    
    // Monitor blocking operations
    for (let i = 0; i < 1000000; i++) {
      count += Math.random();
    }
    
    const duration = performance.now() - start;
    return duration > 100; // More than 100ms for simple loop
  }

  detectSuspiciousNetworkPatterns() {
    // Check for rapid, small requests (keylogging pattern)
    const requests = this.networkRequestLog || [];
    if (requests.length > 20) {
      const recent = requests.slice(-20);
      const avgSize = recent.reduce((a, b) => a + b.size, 0) / recent.length;
      const avgInterval = recent.reduce((a, b, i, arr) => {
        if (i === 0) return 0;
        return a + (b.timestamp - arr[i-1].timestamp);
      }, 0) / (recent.length - 1);
      
      return avgSize < 100 && avgInterval < 1000; // Small requests frequently
    }
    return false;
  }

  // ==================== 5. BEREINIGUNGS-FUNKTIONEN ====================
  executeCleanup(scanResults) {
    console.log('🧹 Executing cleanup procedures...');
    
    // 1. Clear malicious cookies
    this.cleanMaliciousCookies();
    
    // 2. Clear malicious storage
    this.cleanMaliciousStorage();
    
    // 3. Remove malicious scripts
    this.removeMaliciousScripts();
    
    // 4. Clear cache if infected
    if (this.heuristicScore > 40) {
      this.clearBrowserCache();
    }
    
    // 5. Reset suspicious permissions
    this.resetPermissions();
    
    // 6. Create restore point
    this.createRestorePoint();
  }

  cleanMaliciousCookies() {
    const suspiciousDomains = [
      'tracking', 'analytics', 'ad', 'bitcoin', 'mining',
      'crypto', 'malicious', 'phishing'
    ];
    
    document.cookie.split(';').forEach(cookie => {
      const [name] = cookie.trim().split('=');
      
      // Check cookie name and domain
      if (suspiciousDomains.some(domain => name.toLowerCase().includes(domain))) {
        // Expire for all paths and domains
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=${window.location.hostname};`;
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=.${window.location.hostname};`;
        
        this.cleanedItems.push(`cookie:${name}`);
      }
    });
  }

  cleanMaliciousStorage() {
    // Clear localStorage items from suspicious domains
    const currentDomain = window.location.hostname;
    
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      const value = localStorage.getItem(key);
      
      // Check if storage item is from different domain (cross-site)
      if (key.includes('://') && !key.includes(currentDomain)) {
        this.quarantineItem('cross_domain_storage', key, value);
        localStorage.removeItem(key);
        this.cleanedItems.push(`storage:${key}`);
      }
    }
  }

  removeMaliciousScripts() {
    // Remove known malicious script patterns
    const maliciousPatterns = [
      'coin-hive', 'crypto-loot', 'minero', 'jsecoin',
      'deepminer', 'krypton', 'cryptonight'
    ];
    
    document.querySelectorAll('script').forEach(script => {
      const src = script.src.toLowerCase();
      const content = script.textContent.toLowerCase();
      
      if (maliciousPatterns.some(pattern => src.includes(pattern) || content.includes(pattern))) {
        script.remove();
        this.cleanedItems.push(`script:${src || 'inline'}`);
      }
    });
  }

  clearBrowserCache() {
    // Clear cache by reloading with cache-busting headers
    if ('caches' in window) {
      caches.keys().then(cacheNames => {
        cacheNames.forEach(cacheName => {
          caches.delete(cacheName);
        });
      });
    }
    
    // Clear service worker cache
    if (navigator.serviceWorker) {
      navigator.serviceWorker.getRegistrations().then(registrations => {
        registrations.forEach(registration => {
          registration.unregister();
        });
      });
    }
    
    // Force reload without cache
    setTimeout(() => {
      window.location.reload(true);
    }, 1000);
  }

  // ==================== 6. PRÄVENTIVE SCHUTZMASSNAHMEN ====================
  setupProtectionBarriers() {
    // Content Security Policy
    this.enforceCSP();
    
    // XSS Protection
    this.enableXSSProtection();
    
    // Clickjacking protection
    this.preventClickjacking();
    
    // MIME sniffing protection
    this.preventMIMESniffing();
    
    // Referrer policy
    this.setReferrerPolicy();
    
    // Feature policy
    this.setFeaturePolicy();
  }

  enforceCSP() {
    const cspMeta = document.createElement('meta');
    cspMeta.httpEquiv = 'Content-Security-Policy';
    cspMeta.content = `
      default-src 'self';
      script-src 'self' 'unsafe-inline' 'unsafe-eval';
      style-src 'self' 'unsafe-inline';
      img-src 'self' data: https:;
      font-src 'self';
      connect-src 'self';
      media-src 'self';
      object-src 'none';
      frame-src 'self';
      frame-ancestors 'none';
      base-uri 'self';
      form-action 'self';
    `.replace(/\s+/g, ' ');
    
    document.head.appendChild(cspMeta);
  }

  enableXSSProtection() {
    const xssMeta = document.createElement('meta');
    xssMeta.httpEquiv = 'X-XSS-Protection';
    xssMeta.content = '1; mode=block';
    document.head.appendChild(xssMeta);
  }

  preventClickjacking() {
    const frameMeta = document.createElement('meta');
    frameMeta.httpEquiv = 'X-Frame-Options';
    frameMeta.content = 'DENY';
    document.head.appendChild(frameMeta);
  }

  // ==================== 7. QUARANTÄNE SYSTEM ====================
  quarantineItem(type, identifier, data) {
    const quarantineEntry = {
      id: 'Q_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toISOString(),
      type: type,
      identifier: identifier,
      data: typeof data === 'string' ? data.substring(0, 1000) : data,
      originalSize: typeof data === 'string' ? data.length : 0,
      restored: false
    };
    
    this.quarantine.push(quarantineEntry);
    
    // Store in localStorage for persistence
    const quarantineStorage = JSON.parse(localStorage.getItem('malware_quarantine') || '[]');
    quarantineStorage.push(quarantineEntry);
    localStorage.setItem('malware_quarantine', JSON.stringify(quarantineStorage.slice(-50))); // Keep last 50 items
    
    return quarantineEntry.id;
  }

  restoreFromQuarantine(quarantineId) {
    const entry = this.quarantine.find(item => item.id === quarantineId);
    if (!entry || entry.restored) return false;
    
    switch(entry.type) {
      case 'localStorage':
        localStorage.setItem(entry.identifier, entry.data);
        break;
      case 'cookie':
        document.cookie = `${entry.identifier}=${entry.data}; path=/; max-age=2592000`;
        break;
      // Add more restore types as needed
    }
    
    entry.restored = true;
    entry.restoredAt = new Date().toISOString();
    
    return true;
  }

  // ==================== 8. DETEKTIONS-FUNKTIONEN ====================
  detectMaliciousURL(url) {
    if (!url) return false;
    
    const urlStr = url.toString().toLowerCase();
    const maliciousPatterns = [
      // Cryptominers
      /coin-hive/, /crypto-loot/, /minero/, /jsecoin/, /deepminer/,
      /krypton/, /cryptonight/, /webassembly.*mining/,
      
      // Malware domains
      /malware/, /virus/, /trojan/, /ransomware/, /spyware/,
      /keylogger/, /rat\b/, /botnet/, /exploit/,
      
      // Suspicious TLDs
      /\.xyz\//, /\.top\//, /\.win\//, /\.bid\//, /\.stream\//,
      
      // Data exfiltration
      /pastebin\.com\/raw/, /github\.io.*miner/, /bit\.ly.*js/,
      
      // Browser exploits
      /exploit/, /vulnerability/, /zero-day/, /cve-\d{4}-\d+/,
      
      // Phishing
      /login\.fake/, /verify-account/, /security-update/,
      
      // Obfuscated URLs
      /%[0-9a-f]{2}/, /\\x[0-9a-f]{2}/, /&#x[0-9a-f]{2};/
    ];
    
    return maliciousPatterns.some(pattern => pattern.test(urlStr));
  }

  detectMaliciousCode(code) {
    if (!code || typeof code !== 'string') return false;
    
    const codeStr = code.toLowerCase();
    
    // Check all signature categories
    for (const category in MALWARE_SIGNATURES.js) {
      if (MALWARE_SIGNATURES.js[category].some(pattern => pattern.test(codeStr))) {
        return true;
      }
    }
    
    // Check generic patterns
    for (const pattern of MALWARE_SIGNATURES.patterns.obfuscated) {
      if (pattern.test(codeStr)) {
        return true;
      }
    }
    
    // Heuristic: eval with encoded strings
    if (codeStr.includes('eval(') && 
        (codeStr.includes('string.fromcharcode') || 
         codeStr.includes('unescape(') ||
         codeStr.match(/\\x[0-9a-f]{2}/g)?.length > 5)) {
      return true;
    }
    
    // Heuristic: excessive escaping
    const escapeRatio = (codeStr.match(/\\[x0-9a-f]/g) || []).length / codeStr.length;
    if (escapeRatio > 0.1) {
      return true;
    }
    
    return false;
  }

  detectObfuscatedCode(code) {
    if (!code) return false;
    
    const obfuscationPatterns = [
      /eval\(.*String\.fromCharCode/,
      /\\x[0-9a-f]{2}/g,
      /unescape\(.*%/,
      /%[0-9a-f]{2}/g,
      /&#x[0-9a-f]{2};/g,
      /window\[''\+''\]/,
      /\[.*\].*\[.*\]/,
      /\('.*'\)\.call/,
      /function\(\)\{.*\}\(\)/
    ];
    
    let score = 0;
    obfuscationPatterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) score += matches.length;
    });
    
    // Calculate density of special characters
    const specialChars = code.match(/[^a-zA-Z0-9\s]/g) || [];
    const specialCharRatio = specialChars.length / code.length;
    
    if (specialCharRatio > 0.3) score += 5;
    
    return score > 10;
  }

  // ==================== 9. REPORTING & DASHBOARD ====================
  generateScanReport(results) {
    const report = {
      generatedAt: new Date().toISOString(),
      url: window.location.href,
      userAgent: navigator.userAgent,
      summary: {
        totalScans: results.scans.length,
        threatsFound: results.scans.reduce((sum, scan) => sum + scan.threats.length, 0),
        itemsCleaned: this.cleanedItems.length,
        heuristicScore: this.heuristicScore,
        riskLevel: this.calculateRiskLevel(this.heuristicScore)
      },
      detailedResults: results.scans,
      quarantinedItems: this.quarantine.slice(-10),
      recommendations: this.generateRecommendations(results)
    };
    
    // Store report
    localStorage.setItem('last_scan_report', JSON.stringify(report));
    
    // Display to user
    this.displayScanResults(report);
    
    return report;
  }

  calculateRiskLevel(score) {
    if (score >= 70) return 'CRITICAL';
    if (score >= 50) return 'HIGH';
    if (score >= 30) return 'MEDIUM';
    if (score >= 10) return 'LOW';
    return 'SAFE';
  }

  generateRecommendations(results) {
    const recommendations = [];
    
    if (this.heuristicScore > 50) {
      recommendations.push({
        priority: 'HIGH',
        action: 'IMMEDIATE_BROWSER_RESTART',
        description: 'Critical threat detected. Restart browser immediately.'
      });
    }
    
    if (results.scans.some(s => s.type === 'SCRIPTS' && s.threats.length > 0)) {
      recommendations.push({
        priority: 'HIGH',
        action: 'CLEAR_BROWSER_DATA',
        description: 'Malicious scripts found. Clear all browser data.'
      });
    }
    
    if (this.quarantine.length > 5) {
      recommendations.push({
        priority: 'MEDIUM',
        action: 'FULL_SYSTEM_SCAN',
        description: 'Multiple items quarantined. Run full system antivirus scan.'
      });
    }
    
    return recommendations;
  }

  showSecurityDashboard() {
    // Create floating security dashboard
    const dashboard = document.createElement('div');
    dashboard.id = 'malware-defense-dashboard';
    dashboard.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: #1a1a1a;
      color: white;
      border: 2px solid #00ff00;
      border-radius: 10px;
      padding: 15px;
      z-index: 99999;
      max-width: 300px;
      font-family: Arial, sans-serif;
      box-shadow: 0 4px 20px rgba(0,0,0,0.5);
    `;
    
    const statusColor = this.heuristicScore > 50 ? '#ff4444' : 
                       this.heuristicScore > 20 ? '#ffaa00' : '#00ff00';
    
    dashboard.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
        <h3 style="margin: 0; color: ${statusColor};">🛡️ Malware Defense</h3>
        <button onclick="document.getElementById('malware-defense-dashboard').remove()" 
                style="background: none; border: none; color: white; cursor: pointer; font-size: 20px;">
          ×
        </button>
      </div>
      <div style="margin-bottom: 10px;">
        <div>Status: <span style="color: ${statusColor}; font-weight: bold;">
          ${this.calculateRiskLevel(this.heuristicScore)}
        </span></div>
        <div>Threats blocked: <span style="color: #00aaff;">${this.threatsDetected.length}</span></div>
        <div>Last scan: <span style="color: #aaa;">${new Date().toLocaleTimeString()}</span></div>
      </div>
      <div style="display: flex; gap: 10px;">
        <button onclick="window.malwareDefense.performFullSystemScan()"
                style="flex: 1; background: #0066cc; color: white; border: none; padding: 8px; border-radius: 5px; cursor: pointer;">
          🔍 Scan Now
        </button>
        <button onclick="window.malwareDefense.showDetailedReport()"
                style="flex: 1; background: #333; color: white; border: none; padding: 8px; border-radius: 5px; cursor: pointer;">
          📊 Report
        </button>
      </div>
    `;
    
    document.body.appendChild(dashboard);
    
    // Auto-hide after 30 seconds
    setTimeout(() => {
      if (dashboard.parentNode) {
        dashboard.style.opacity = '0.5';
      }
    }, 30000);
  }

  showDetailedReport() {
    const report = JSON.parse(localStorage.getItem('last_scan_report') || '{}');
    
    const modal = document.createElement('div');
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.8);
      z-index: 100000;
      display: flex;
      align-items: center;
      justify-content: center;
    `;
    
    modal.innerHTML = `
      <div style="background: white; color: black; padding: 20px; border-radius: 10px; max-width: 800px; max-height: 80vh; overflow-y: auto;">
        <h2>🔒 Security Scan Report</h2>
        <div style="margin-bottom: 20px;">
          <p><strong>Generated:</strong> ${report.generatedAt || 'N/A'}</p>
          <p><strong>Risk Level:</strong> <span style="color: ${report.summary?.riskLevel === 'CRITICAL' ? 'red' : 'orange'}">
            ${report.summary?.riskLevel || 'N/A'}
          </span></p>
          <p><strong>Threats Found:</strong> ${report.summary?.threatsFound || 0}</p>
        </div>
        
        <h3>Detailed Results</h3>
        <div style="max-height: 300px; overflow-y: auto; margin-bottom: 20px;">
          ${report.detailedResults ? report.detailedResults.map(scan => `
            <div style="border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; border-radius: 5px;">
              <h4 style="margin: 0 0 10px 0;">${scan.type}</h4>
              ${scan.threats.length > 0 ? 
                `<ul style="margin: 0; padding-left: 20px; color: red;">
                  ${scan.threats.map(t => `<li>${t.type}: ${t.action}</li>`).join('')}
                </ul>` : 
                '<p style="color: green; margin: 0;">✓ No threats found</p>'
              }
            </div>
          `).join('') : '<p>No scan data available</p>'}
        </div>
        
        <button onclick="this.parentElement.parentElement.remove()"
                style="background: #0066cc; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
          Close
        </button>
      </div>
    `;
    
    document.body.appendChild(modal);
  }

  // ==================== 10. AUTO-CLEANUP SCHEDULER ====================
  startAutoCleanupScheduler() {
    // Scheduled scans every 5 minutes
    setInterval(() => {
      this.performLightScan();
    }, MALWARE_DEFENSE_CONFIG.detection.scanInterval);
    
    // Deep scan every hour
    setInterval(() => {
      this.performFullSystemScan();
    }, 3600000);
    
    // Auto-cleanup every 10 minutes
    setInterval(() => {
      this
