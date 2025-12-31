/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Web Technology Detection Tool (FREE - No API Keys Required)
 *
 * ENHANCED VERSION with reduced false positives and false negatives.
 *
 * Detects web technologies by analyzing:
 * - HTTP response headers (Server, X-Powered-By, etc.)
 * - HTML meta tags (generator, framework-specific)
 * - Script src attributes (library paths)
 * - Link stylesheet hrefs (CSS frameworks)
 * - HTML data attributes (framework-specific)
 * - Cookie patterns (session identifiers)
 * - HTML comments (CMS signatures)
 * - Inline scripts (framework initialization)
 * - WAF/CDN fingerprints
 *
 * Detection confidence levels:
 * - HIGH: Direct header evidence or explicit version/signature
 * - MEDIUM: Multiple corroborating patterns found
 * - LOW: Single pattern match that could have alternatives
 *
 * Similar to Wappalyzer/BuiltWith but completely free and local.
 */

import type { Config } from '../config/config.js';
import { ToolErrorType } from './tool-error.js';
import type { ToolInvocation, ToolResult } from './tools.js';
import { BaseDeclarativeTool, BaseToolInvocation, Kind } from './tools.js';
import { ToolNames, ToolDisplayNames } from './tool-names.js';
import {
  formatCVEIntelligenceSection,
  type DetectedProduct,
} from './cve-intelligence-helper.js';

const FETCH_TIMEOUT_MS = 15000;

/**
 * Technology categories
 */
export type TechCategory =
  | 'web-server'
  | 'programming-language'
  | 'framework'
  | 'cms'
  | 'cdn'
  | 'waf'
  | 'analytics'
  | 'javascript'
  | 'css-framework'
  | 'database'
  | 'cache'
  | 'security'
  | 'hosting'
  | 'e-commerce'
  | 'other';

/**
 * Detected technology
 */
export interface DetectedTechnology {
  name: string;
  category: TechCategory;
  version?: string;
  confidence: 'high' | 'medium' | 'low';
  evidence: string;
}

/**
 * Parameters for the Web Tech tool
 */
export interface WebTechToolParams {
  /**
   * URL to analyze
   */
  url: string;
  /**
   * Include full headers in output
   */
  includeHeaders?: boolean;
  /**
   * Follow redirects
   */
  followRedirects?: boolean;
}

/**
 * Technology signatures database
 */
const TECH_SIGNATURES = {
  // Web Servers (from Server header)
  servers: [
    {
      pattern: /nginx\/?(\d+[\d.]*)?/i,
      name: 'nginx',
      category: 'web-server' as TechCategory,
    },
    {
      pattern: /apache\/?(\d+[\d.]*)?/i,
      name: 'Apache',
      category: 'web-server' as TechCategory,
    },
    {
      pattern: /microsoft-iis\/?(\d+[\d.]*)?/i,
      name: 'Microsoft IIS',
      category: 'web-server' as TechCategory,
    },
    {
      pattern: /^gws$/i,
      name: 'Google Web Server',
      category: 'web-server' as TechCategory,
    },
    {
      pattern: /cloudflare/i,
      name: 'Cloudflare',
      category: 'cdn' as TechCategory,
    },
    {
      pattern: /^AmazonS3$/i,
      name: 'Amazon S3',
      category: 'hosting' as TechCategory,
    },
    {
      pattern: /gunicorn\/?(\d+[\d.]*)?/i,
      name: 'Gunicorn',
      category: 'web-server' as TechCategory,
    },
    {
      pattern: /openresty\/?(\d+[\d.]*)?/i,
      name: 'OpenResty',
      category: 'web-server' as TechCategory,
    },
    {
      pattern: /LiteSpeed/i,
      name: 'LiteSpeed',
      category: 'web-server' as TechCategory,
    },
    {
      pattern: /caddy/i,
      name: 'Caddy',
      category: 'web-server' as TechCategory,
    },
    {
      pattern: /Cowboy/i,
      name: 'Cowboy (Erlang)',
      category: 'web-server' as TechCategory,
    },
    {
      pattern: /Kestrel/i,
      name: 'Kestrel (.NET)',
      category: 'web-server' as TechCategory,
    },
    { pattern: /Vercel/i, name: 'Vercel', category: 'hosting' as TechCategory },
    {
      pattern: /Netlify/i,
      name: 'Netlify',
      category: 'hosting' as TechCategory,
    },
  ],

  // Programming languages (from X-Powered-By, etc.)
  languages: [
    {
      pattern: /PHP\/?(\d+[\d.]*)?/i,
      name: 'PHP',
      category: 'programming-language' as TechCategory,
    },
    {
      pattern: /ASP\.NET/i,
      name: 'ASP.NET',
      category: 'programming-language' as TechCategory,
    },
    {
      pattern: /Express/i,
      name: 'Express.js (Node.js)',
      category: 'framework' as TechCategory,
    },
    {
      pattern: /Next\.js\/?(\d+[\d.]*)?/i,
      name: 'Next.js',
      category: 'framework' as TechCategory,
    },
    {
      pattern: /Phusion Passenger/i,
      name: 'Passenger (Ruby)',
      category: 'web-server' as TechCategory,
    },
    {
      pattern: /Python\/?(\d+[\d.]*)?/i,
      name: 'Python',
      category: 'programming-language' as TechCategory,
    },
    {
      pattern: /Django/i,
      name: 'Django',
      category: 'framework' as TechCategory,
    },
    { pattern: /Flask/i, name: 'Flask', category: 'framework' as TechCategory },
    {
      pattern: /Ruby/i,
      name: 'Ruby',
      category: 'programming-language' as TechCategory,
    },
    {
      pattern: /Rails/i,
      name: 'Ruby on Rails',
      category: 'framework' as TechCategory,
    },
    {
      pattern: /Servlet/i,
      name: 'Java Servlet',
      category: 'programming-language' as TechCategory,
    },
  ],

  // CDN/Proxy (from headers)
  cdn: [
    { header: 'cf-ray', name: 'Cloudflare', category: 'cdn' as TechCategory },
    { header: 'x-cdn', name: 'CDN', category: 'cdn' as TechCategory },
    {
      header: 'x-cache',
      pattern: /HIT|MISS/i,
      name: 'CDN Cache',
      category: 'cache' as TechCategory,
    },
    {
      header: 'x-served-by',
      pattern: /cache/i,
      name: 'Varnish/Fastly',
      category: 'cache' as TechCategory,
    },
    {
      header: 'x-fastly-request-id',
      name: 'Fastly',
      category: 'cdn' as TechCategory,
    },
    {
      header: 'x-amz-cf-id',
      name: 'Amazon CloudFront',
      category: 'cdn' as TechCategory,
    },
    {
      header: 'x-akamai-transformed',
      name: 'Akamai',
      category: 'cdn' as TechCategory,
    },
    { header: 'x-sucuri-id', name: 'Sucuri', category: 'waf' as TechCategory },
    { header: 'x-varnish', name: 'Varnish', category: 'cache' as TechCategory },
  ],

  // WAF detection
  waf: [
    {
      header: 'x-sucuri-id',
      name: 'Sucuri WAF',
      category: 'waf' as TechCategory,
    },
    {
      header: 'x-sucuri-cache',
      name: 'Sucuri WAF',
      category: 'waf' as TechCategory,
    },
    {
      header: 'x-cdn',
      pattern: /imperva/i,
      name: 'Imperva Incapsula',
      category: 'waf' as TechCategory,
    },
    {
      header: 'x-iinfo',
      name: 'Imperva Incapsula',
      category: 'waf' as TechCategory,
    },
    {
      header: 'x-protected-by',
      pattern: /sqreen/i,
      name: 'Sqreen',
      category: 'waf' as TechCategory,
    },
    {
      header: 'server',
      pattern: /cloudflare/i,
      name: 'Cloudflare WAF',
      category: 'waf' as TechCategory,
    },
    {
      header: 'server',
      pattern: /AkamaiGHost/i,
      name: 'Akamai WAF',
      category: 'waf' as TechCategory,
    },
    {
      header: 'x-fw-hash',
      name: 'Barracuda WAF',
      category: 'waf' as TechCategory,
    },
    {
      header: 'server',
      pattern: /BigIP/i,
      name: 'F5 BIG-IP',
      category: 'waf' as TechCategory,
    },
    {
      header: 'x-denied-reason',
      name: 'WAF Block',
      category: 'waf' as TechCategory,
    },
  ],

  // Security headers
  securityHeaders: [
    {
      header: 'strict-transport-security',
      name: 'HSTS',
      category: 'security' as TechCategory,
    },
    {
      header: 'content-security-policy',
      name: 'CSP (Enforced)',
      category: 'security' as TechCategory,
    },
    {
      header: 'content-security-policy-report-only',
      name: 'CSP (Report Only)',
      category: 'security' as TechCategory,
    },
    {
      header: 'x-frame-options',
      name: 'X-Frame-Options',
      category: 'security' as TechCategory,
    },
    {
      header: 'x-content-type-options',
      name: 'X-Content-Type-Options',
      category: 'security' as TechCategory,
    },
    {
      header: 'x-xss-protection',
      name: 'X-XSS-Protection',
      category: 'security' as TechCategory,
    },
    {
      header: 'permissions-policy',
      name: 'Permissions-Policy',
      category: 'security' as TechCategory,
    },
    {
      header: 'referrer-policy',
      name: 'Referrer-Policy',
      category: 'security' as TechCategory,
    },
    {
      header: 'cross-origin-opener-policy',
      name: 'COOP',
      category: 'security' as TechCategory,
    },
    {
      header: 'cross-origin-embedder-policy',
      name: 'COEP',
      category: 'security' as TechCategory,
    },
    {
      header: 'cross-origin-resource-policy',
      name: 'CORP',
      category: 'security' as TechCategory,
    },
  ],

  // HTML patterns for CMS detection (ENHANCED - more precise patterns)
  cms: [
    // WordPress - multiple specific indicators
    {
      pattern: /\/wp-content\/|\/wp-includes\/|\/wp-admin\//i,
      name: 'WordPress',
      category: 'cms' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern:
        /<meta\s+name=["']generator["']\s+content=["']WordPress[^"']*["']/i,
      name: 'WordPress',
      category: 'cms' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern: /wp-emoji|wp-block-|wpcf7|wp-json|xmlrpc\.php/i,
      name: 'WordPress',
      category: 'cms' as TechCategory,
      confidenceBoost: false,
    },
    // Drupal - specific paths
    {
      pattern: /\/sites\/default\/files\/|\/sites\/all\/|drupal\.js/i,
      name: 'Drupal',
      category: 'cms' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern: /<meta\s+name=["']generator["']\s+content=["']Drupal[^"']*["']/i,
      name: 'Drupal',
      category: 'cms' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern: /Drupal\.settings|drupal-ajax/i,
      name: 'Drupal',
      category: 'cms' as TechCategory,
      confidenceBoost: false,
    },
    // Joomla - specific paths
    {
      pattern:
        /\/media\/system\/js\/|\/administrator\/components\/|\/components\/com_/i,
      name: 'Joomla',
      category: 'cms' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern: /<meta\s+name=["']generator["']\s+content=["']Joomla[^"']*["']/i,
      name: 'Joomla',
      category: 'cms' as TechCategory,
      confidenceBoost: true,
    },
    // Shopify - specific domains/patterns
    {
      pattern: /cdn\.shopify\.com|shopify-section|Shopify\.theme/i,
      name: 'Shopify',
      category: 'e-commerce' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern: /myshopify\.com|shopify-payment/i,
      name: 'Shopify',
      category: 'e-commerce' as TechCategory,
      confidenceBoost: true,
    },
    // Wix
    {
      pattern: /static\.wixstatic\.com|wix-code-|_wixCIDX/i,
      name: 'Wix',
      category: 'cms' as TechCategory,
      confidenceBoost: true,
    },
    // Squarespace
    {
      pattern:
        /static1\.squarespace\.com|squarespace-cdn|sqs-|\.squarespace\.com/i,
      name: 'Squarespace',
      category: 'cms' as TechCategory,
      confidenceBoost: true,
    },
    // Ghost
    {
      pattern:
        /ghost\.io\/|ghost-(?:url|api|admin)|<meta\s+name=["']generator["']\s+content=["']Ghost/i,
      name: 'Ghost',
      category: 'cms' as TechCategory,
      confidenceBoost: true,
    },
    // Webflow
    {
      pattern: /webflow\.com\/|wf-|w-nav-|w-dropdown/i,
      name: 'Webflow',
      category: 'cms' as TechCategory,
      confidenceBoost: true,
    },
    // HubSpot
    {
      pattern: /js\.hs-scripts\.com|hs-script-loader|hsforms\.net|hubspot/i,
      name: 'HubSpot',
      category: 'cms' as TechCategory,
      confidenceBoost: true,
    },
    // Contentful
    {
      pattern: /contentful\.com|ctfassets\.net/i,
      name: 'Contentful',
      category: 'cms' as TechCategory,
      confidenceBoost: true,
    },
    // Magento - more specific patterns to avoid false positives
    {
      pattern:
        /\/static\/(?:version\d+\/)?frontend\/[^/]+\/[^/]+\/|data-mage-init=|Magento_[A-Z][a-z]+|require\.config\s*\(\s*\{\s*["']baseUrl["']/i,
      name: 'Magento',
      category: 'e-commerce' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern:
        /\/pub\/static\/|\/media\/catalog\/product|mage\/mage\.js|mage\/requirejs/i,
      name: 'Magento',
      category: 'e-commerce' as TechCategory,
      confidenceBoost: false,
    },
    // PrestaShop
    {
      pattern: /prestashop|PrestaShop|\/modules\/ps_/i,
      name: 'PrestaShop',
      category: 'e-commerce' as TechCategory,
      confidenceBoost: true,
    },
    // WooCommerce
    {
      pattern: /woocommerce|wc-blocks|wc-cart-fragments/i,
      name: 'WooCommerce',
      category: 'e-commerce' as TechCategory,
      confidenceBoost: true,
    },
    // Strapi
    {
      pattern: /strapi\.io|\/uploads\/|strapi-/i,
      name: 'Strapi',
      category: 'cms' as TechCategory,
      confidenceBoost: false,
    },
    // Craft CMS
    {
      pattern: /craft-datepicker|Craft\.LivePreview|craftcms/i,
      name: 'Craft CMS',
      category: 'cms' as TechCategory,
      confidenceBoost: true,
    },
    // Typo3
    {
      pattern: /typo3|TYPO3\.settings|\/typo3temp\//i,
      name: 'TYPO3',
      category: 'cms' as TechCategory,
      confidenceBoost: true,
    },
    // BigCommerce
    {
      pattern: /bigcommerce\.com|data-core-|stencil-/i,
      name: 'BigCommerce',
      category: 'e-commerce' as TechCategory,
      confidenceBoost: true,
    },
  ],

  // JavaScript frameworks (ENHANCED - more precise patterns to reduce false positives)
  jsFrameworks: [
    // React - require more specific patterns, not just "react" word
    {
      pattern: /__NEXT_DATA__|_next\/static|nextjs/i,
      name: 'Next.js',
      category: 'framework' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern:
        /react-dom|react\.production\.min\.js|react\.development\.js|reactDOM|data-reactroot|data-reactid/i,
      name: 'React',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern: /\breact[.-](?:dom|router|redux)|createRoot|ReactDOM\.render/i,
      name: 'React',
      category: 'javascript' as TechCategory,
      confidenceBoost: false,
    },
    // Vue.js - require more specific patterns
    {
      pattern:
        /vue\.runtime|vue\.global|vue@\d|__VUE__|data-v-[a-f0-9]{8}|v-cloak|v-if=|v-for=|v-bind:/i,
      name: 'Vue.js',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern: /vue\.(?:min\.)?js|\.vue\b|vue-router|vuex|@vue\//i,
      name: 'Vue.js',
      category: 'javascript' as TechCategory,
      confidenceBoost: false,
    },
    // Angular - require Angular-specific attributes/patterns
    {
      pattern:
        /ng-version=|angular\.(?:min\.)?js|@angular\/|ng-app=["'][^"']+["']|ng-controller=["'][^"']+["']/i,
      name: 'Angular',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern: /\[ngClass\]|\(click\)=|\*ngIf=|\*ngFor=|_ngcontent-|_nghost-/i,
      name: 'Angular',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
    // Svelte - specific patterns
    {
      pattern: /__svelte|svelte-[a-z0-9]+|\.svelte\b|sveltekit/i,
      name: 'Svelte',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
    // jQuery - require script src or specific usage
    {
      pattern: /jquery[.-]\d|jquery\.min\.js|jquery\.slim|jquery-migrate/i,
      name: 'jQuery',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern: /\$\(document\)\.ready|\$\(["']#|\$\(["']\./i,
      name: 'jQuery',
      category: 'javascript' as TechCategory,
      confidenceBoost: false,
    },
    // Bootstrap - require specific file patterns
    {
      pattern: /bootstrap[.-]\d|bootstrap\.min\.(?:js|css)|bootstrap\.bundle/i,
      name: 'Bootstrap',
      category: 'css-framework' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern:
        /class=["'][^"']*\b(?:container-fluid|col-(?:xs|sm|md|lg|xl)-\d{1,2}|btn-(?:primary|secondary|success|danger))\b/i,
      name: 'Bootstrap',
      category: 'css-framework' as TechCategory,
      confidenceBoost: false,
    },
    // Tailwind CSS - specific utility class patterns
    {
      pattern:
        /tailwindcss|tailwind\.(?:min\.)?css|@tailwind\s+(?:base|components|utilities)/i,
      name: 'Tailwind CSS',
      category: 'css-framework' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern:
        /class=["'][^"']*(?:flex\s+items-center|p-\d+\s+m-\d+|text-(?:sm|lg|xl)|bg-(?:blue|red|green|gray)-\d{2,3})[^"']*["']/i,
      name: 'Tailwind CSS',
      category: 'css-framework' as TechCategory,
      confidenceBoost: false,
    },
    // Ember.js
    {
      pattern: /ember\.(?:min\.)?js|ember-cli|@ember\//i,
      name: 'Ember.js',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
    // Backbone.js
    {
      pattern:
        /backbone\.(?:min\.)?js|Backbone\.(?:Model|View|Router|Collection)/i,
      name: 'Backbone.js',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
    // Alpine.js - require x-data with actual content
    {
      pattern: /alpinejs|alpine\.(?:min\.)?js|x-data=["']\{/i,
      name: 'Alpine.js',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
    // htmx
    {
      pattern: /htmx\.(?:min\.)?js|hx-get=|hx-post=|hx-target=/i,
      name: 'htmx',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
    // Gatsby
    {
      pattern: /gatsby-|___gatsby|gatsby\.js/i,
      name: 'Gatsby',
      category: 'framework' as TechCategory,
      confidenceBoost: true,
    },
    // Nuxt.js
    {
      pattern: /__nuxt|nuxt\.js|\.nuxt\//i,
      name: 'Nuxt.js',
      category: 'framework' as TechCategory,
      confidenceBoost: true,
    },
    // Additional modern frameworks
    {
      pattern: /astro-[a-z0-9]+|\.astro\b|@astrojs\//i,
      name: 'Astro',
      category: 'framework' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern: /solid-js|@solidjs\/|createSignal|createEffect/i,
      name: 'SolidJS',
      category: 'javascript' as TechCategory,
      confidenceBoost: false,
    },
    {
      pattern: /__remix|@remix-run|remix\.config/i,
      name: 'Remix',
      category: 'framework' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern: /stimulus\.(?:min\.)?js|data-controller=|data-action=.*->/i,
      name: 'Stimulus',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern: /turbo\.(?:min\.)?js|turbo-frame|turbo-stream/i,
      name: 'Turbo',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern: /preact\.(?:min\.)?js|@preact\//i,
      name: 'Preact',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
    // Lodash/Underscore
    {
      pattern: /lodash\.(?:min\.)?js|underscore\.(?:min\.)?js/i,
      name: 'Lodash/Underscore',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
    // Axios
    {
      pattern: /axios\.(?:min\.)?js|axios@\d/i,
      name: 'Axios',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
    // Moment.js
    {
      pattern: /moment\.(?:min\.)?js|moment-timezone/i,
      name: 'Moment.js',
      category: 'javascript' as TechCategory,
      confidenceBoost: true,
    },
  ],

  // Analytics (ENHANCED - more precise patterns to avoid false matches)
  analytics: [
    // Google Analytics - require specific script or ID format
    {
      pattern:
        /google-analytics\.com\/(?:analytics|ga)\.js|googletagmanager\.com\/gtag/i,
      name: 'Google Analytics',
      category: 'analytics' as TechCategory,
      confidenceBoost: true,
    },
    {
      pattern: /\b(?:UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{10,})\b/i,
      name: 'Google Analytics',
      category: 'analytics' as TechCategory,
      confidenceBoost: true,
    },
    // Google Tag Manager
    {
      pattern: /googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]{4,}/i,
      name: 'Google Tag Manager',
      category: 'analytics' as TechCategory,
      confidenceBoost: true,
    },
    // Facebook Pixel
    {
      pattern:
        /connect\.facebook\.net\/.*\/fbevents\.js|fbq\s*\(\s*['"]init['"]/i,
      name: 'Facebook Pixel',
      category: 'analytics' as TechCategory,
      confidenceBoost: true,
    },
    // Hotjar
    {
      pattern: /static\.hotjar\.com|hjSiteSettings|hj\s*\(\s*['"]identify['"]/i,
      name: 'Hotjar',
      category: 'analytics' as TechCategory,
      confidenceBoost: true,
    },
    // Microsoft Clarity
    {
      pattern: /clarity\.ms\/tag\/|clarity\s*\(\s*['"]/i,
      name: 'Microsoft Clarity',
      category: 'analytics' as TechCategory,
      confidenceBoost: true,
    },
    // Mixpanel
    {
      pattern: /cdn\.mxpnl\.com|mixpanel\.com\/libs\/|mixpanel\.init/i,
      name: 'Mixpanel',
      category: 'analytics' as TechCategory,
      confidenceBoost: true,
    },
    // Segment
    {
      pattern: /cdn\.segment\.com\/analytics\.js|analytics\.load\s*\(/i,
      name: 'Segment',
      category: 'analytics' as TechCategory,
      confidenceBoost: true,
    },
    // Plausible
    {
      pattern: /plausible\.io\/js\/|data-domain=.*plausible/i,
      name: 'Plausible',
      category: 'analytics' as TechCategory,
      confidenceBoost: true,
    },
    // Matomo/Piwik
    {
      pattern: /matomo\.js|piwik\.js|_paq\.push/i,
      name: 'Matomo/Piwik',
      category: 'analytics' as TechCategory,
      confidenceBoost: true,
    },
    // Heap
    {
      pattern: /heapanalytics\.com|heap\.load\s*\(/i,
      name: 'Heap',
      category: 'analytics' as TechCategory,
      confidenceBoost: true,
    },
    // Amplitude
    {
      pattern: /amplitude\.com\/libs\/|amplitude\.getInstance/i,
      name: 'Amplitude',
      category: 'analytics' as TechCategory,
      confidenceBoost: true,
    },
    // PostHog
    {
      pattern: /posthog\.com\/static\/|posthog\.init/i,
      name: 'PostHog',
      category: 'analytics' as TechCategory,
      confidenceBoost: true,
    },
    // Fathom
    {
      pattern: /cdn\.usefathom\.com|fathom\.trackPageview/i,
      name: 'Fathom',
      category: 'analytics' as TechCategory,
      confidenceBoost: true,
    },
    // Simple Analytics
    {
      pattern: /simpleanalyticscdn\.com|sa\.latest\.js/i,
      name: 'Simple Analytics',
      category: 'analytics' as TechCategory,
      confidenceBoost: true,
    },
  ],
};

/**
 * Fetch with timeout helper
 */
async function fetchWithTimeout(
  url: string,
  timeout: number,
  followRedirects: boolean = true,
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      redirect: followRedirects ? 'follow' : 'manual',
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        Accept:
          'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
      },
    });
    return response;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Implementation of the Web Tech detection tool
 */
class WebTechToolInvocation extends BaseToolInvocation<
  WebTechToolParams,
  ToolResult
> {
  constructor(params: WebTechToolParams) {
    super(params);
  }

  getDescription(): string {
    return `Detecting web technologies for: ${this.params.url}`;
  }

  async execute(): Promise<ToolResult> {
    let { url } = this.params;
    const { includeHeaders = false, followRedirects = true } = this.params;

    // Normalize URL
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = `https://${url}`;
    }

    try {
      const response = await fetchWithTimeout(
        url,
        FETCH_TIMEOUT_MS,
        followRedirects,
      );

      const headers = Object.fromEntries(response.headers.entries());
      const html = await response.text();

      const technologies: DetectedTechnology[] = [];
      const securityFindings: string[] = [];

      // === HEADER-BASED DETECTION (High Confidence) ===
      // Analyze Server header
      this.analyzeServerHeader(headers, technologies);

      // Analyze X-Powered-By header
      this.analyzePoweredByHeader(headers, technologies);

      // Analyze CDN/Proxy headers
      this.analyzeCdnHeaders(headers, technologies);

      // Analyze WAF headers
      this.analyzeWafHeaders(headers, technologies);

      // Analyze security headers
      this.analyzeSecurityHeaders(headers, technologies, securityFindings);

      // Analyze cookies
      this.analyzeCookies(headers, technologies);

      // === HTML-BASED DETECTION ===
      // Analyze meta tags (High Confidence - explicit generator tags)
      this.analyzeMetaTags(html, technologies);

      // Analyze script tags (Medium-High Confidence - library URLs)
      this.analyzeScriptTags(html, technologies);

      // Analyze link tags (Medium Confidence - CSS frameworks)
      this.analyzeLinkTags(html, technologies);

      // Analyze HTML comments (Medium Confidence - CMS signatures)
      this.analyzeHtmlComments(html, technologies);

      // Analyze HTML for CMS patterns
      this.analyzeHtmlForCms(html, technologies);

      // Analyze HTML for JavaScript frameworks
      this.analyzeHtmlForJs(html, technologies);

      // Analyze HTML for analytics
      this.analyzeHtmlForAnalytics(html, technologies);

      // === POST-PROCESSING ===
      // Deduplicate and boost confidence for corroborating evidence
      const uniqueTechs = this.deduplicateAndBoostConfidence(technologies);

      return this.formatResults(
        url,
        uniqueTechs,
        securityFindings,
        headers,
        includeHeaders,
        response.status,
      );
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      return {
        llmContent: `Error analyzing ${url}: ${errorMessage}\n\nPossible causes:\n- Website is down or unreachable\n- SSL/TLS certificate issues\n- Firewall/WAF blocking the request\n- Network connectivity issues`,
        returnDisplay: `Failed to analyze ${url}`,
        error: {
          message: errorMessage,
          type: ToolErrorType.EXECUTION_FAILED,
        },
      };
    }
  }

  private analyzeServerHeader(
    headers: Record<string, string>,
    technologies: DetectedTechnology[],
  ): void {
    const server = headers['server'] || headers['Server'];
    if (!server) return;

    for (const sig of TECH_SIGNATURES.servers) {
      const match = server.match(sig.pattern);
      if (match) {
        technologies.push({
          name: sig.name,
          category: sig.category,
          version: match[1] || undefined,
          confidence: 'high',
          evidence: `Server: ${server}`,
        });
      }
    }
  }

  private analyzePoweredByHeader(
    headers: Record<string, string>,
    technologies: DetectedTechnology[],
  ): void {
    const poweredBy = headers['x-powered-by'] || headers['X-Powered-By'];
    if (!poweredBy) return;

    for (const sig of TECH_SIGNATURES.languages) {
      const match = poweredBy.match(sig.pattern);
      if (match) {
        technologies.push({
          name: sig.name,
          category: sig.category,
          version: match[1] || undefined,
          confidence: 'high',
          evidence: `X-Powered-By: ${poweredBy}`,
        });
      }
    }

    // If no match found, add raw powered-by
    if (!technologies.some((t) => t.evidence.includes('X-Powered-By'))) {
      technologies.push({
        name: poweredBy,
        category: 'other',
        confidence: 'high',
        evidence: `X-Powered-By: ${poweredBy}`,
      });
    }
  }

  private analyzeCdnHeaders(
    headers: Record<string, string>,
    technologies: DetectedTechnology[],
  ): void {
    const lowerHeaders = Object.fromEntries(
      Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]),
    );

    for (const sig of TECH_SIGNATURES.cdn) {
      const value = lowerHeaders[sig.header];
      if (value) {
        if (!sig.pattern || sig.pattern.test(value)) {
          technologies.push({
            name: sig.name,
            category: sig.category,
            confidence: 'high',
            evidence: `${sig.header}: ${value}`,
          });
        }
      }
    }
  }

  private analyzeWafHeaders(
    headers: Record<string, string>,
    technologies: DetectedTechnology[],
  ): void {
    const lowerHeaders = Object.fromEntries(
      Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]),
    );

    for (const sig of TECH_SIGNATURES.waf) {
      const value = lowerHeaders[sig.header];
      if (value) {
        if (!sig.pattern || sig.pattern.test(value)) {
          technologies.push({
            name: sig.name,
            category: sig.category,
            confidence: 'high',
            evidence: `${sig.header}: ${value}`,
          });
        }
      }
    }
  }

  private analyzeSecurityHeaders(
    headers: Record<string, string>,
    technologies: DetectedTechnology[],
    findings: string[],
  ): void {
    const lowerHeaders = Object.fromEntries(
      Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]),
    );

    // Check for security headers and add to technologies
    for (const sig of TECH_SIGNATURES.securityHeaders) {
      const value = lowerHeaders[sig.header];
      if (value) {
        technologies.push({
          name: sig.name,
          category: sig.category,
          confidence: 'high',
          evidence: `${sig.header}: ${value.substring(0, 100)}${value.length > 100 ? '...' : ''}`,
        });
      }
    }

    // Check for missing security headers with smart CSP detection
    const cspEnforced = lowerHeaders['content-security-policy'];
    const cspReportOnly = lowerHeaders['content-security-policy-report-only'];

    if (!cspEnforced && !cspReportOnly) {
      findings.push('Missing security header: content-security-policy');
    } else if (!cspEnforced && cspReportOnly) {
      findings.push(
        'CSP is in report-only mode (not enforced) - consider enabling enforcement',
      );
    }

    if (!lowerHeaders['strict-transport-security']) {
      findings.push(
        'Missing security header: strict-transport-security (HSTS)',
      );
    }

    if (
      !lowerHeaders['x-frame-options'] &&
      !lowerHeaders['content-security-policy']?.includes('frame-ancestors')
    ) {
      findings.push(
        'Missing clickjacking protection: x-frame-options or CSP frame-ancestors',
      );
    }

    if (!lowerHeaders['x-content-type-options']) {
      findings.push(
        'Missing security header: x-content-type-options (MIME sniffing protection)',
      );
    }

    // Check for deprecated/weak headers
    const xssProtection = lowerHeaders['x-xss-protection'];
    if (xssProtection === '0') {
      // This is actually correct - XSS filter is disabled intentionally on modern browsers
      // No finding needed
    } else if (xssProtection && !xssProtection.includes('mode=block')) {
      findings.push('X-XSS-Protection should use mode=block if enabled');
    }
  }

  /**
   * Analyze meta tags for generator info (High Confidence)
   */
  private analyzeMetaTags(
    html: string,
    technologies: DetectedTechnology[],
  ): void {
    // Extract meta generator tags
    const generatorMatch = html.match(
      /<meta\s+[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/gi,
    );
    if (generatorMatch) {
      for (const match of generatorMatch) {
        const contentMatch = match.match(/content=["']([^"']+)["']/i);
        if (contentMatch) {
          const generator = contentMatch[1];
          // Extract version if present
          const versionMatch = generator.match(/[\s-]v?(\d+(?:\.\d+)*)/i);
          technologies.push({
            name: generator.split(/[\s-]/)[0] || generator,
            category: 'cms',
            version: versionMatch?.[1],
            confidence: 'high',
            evidence: `meta generator: ${generator}`,
          });
        }
      }
    }

    // Extract framework-specific meta tags
    const frameworkMetas = [
      {
        pattern: /<meta\s+[^>]*name=["']next-head-count["']/i,
        name: 'Next.js',
        category: 'framework' as TechCategory,
      },
      {
        pattern: /<meta\s+[^>]*name=["']nuxt["']/i,
        name: 'Nuxt.js',
        category: 'framework' as TechCategory,
      },
      {
        pattern: /<meta\s+[^>]*name=["']gatsby["']/i,
        name: 'Gatsby',
        category: 'framework' as TechCategory,
      },
      {
        pattern: /<meta\s+[^>]*name=["']remix-run["']/i,
        name: 'Remix',
        category: 'framework' as TechCategory,
      },
    ];

    for (const meta of frameworkMetas) {
      if (meta.pattern.test(html)) {
        technologies.push({
          name: meta.name,
          category: meta.category,
          confidence: 'high',
          evidence: 'Framework-specific meta tag',
        });
      }
    }
  }

  /**
   * Analyze script src attributes for JavaScript libraries (Medium-High Confidence)
   */
  private analyzeScriptTags(
    html: string,
    technologies: DetectedTechnology[],
  ): void {
    // Extract all script src attributes
    const scriptSrcs = html.matchAll(
      /<script[^>]+src=["']([^"']+)["'][^>]*>/gi,
    );

    const knownLibraries = [
      {
        pattern: /jquery[.-](\d+(?:\.\d+)*)/i,
        name: 'jQuery',
        category: 'javascript' as TechCategory,
      },
      {
        pattern: /react(?:\.production)?[.-](\d+(?:\.\d+)*)/i,
        name: 'React',
        category: 'javascript' as TechCategory,
      },
      {
        pattern: /vue(?:\.runtime)?[.-](\d+(?:\.\d+)*)/i,
        name: 'Vue.js',
        category: 'javascript' as TechCategory,
      },
      {
        pattern: /angular(?:\.min)?[.-](\d+(?:\.\d+)*)/i,
        name: 'Angular',
        category: 'javascript' as TechCategory,
      },
      {
        pattern: /bootstrap[.-](\d+(?:\.\d+)*)/i,
        name: 'Bootstrap',
        category: 'css-framework' as TechCategory,
      },
      {
        pattern: /lodash[.-](\d+(?:\.\d+)*)/i,
        name: 'Lodash',
        category: 'javascript' as TechCategory,
      },
      {
        pattern: /axios[.-](\d+(?:\.\d+)*)/i,
        name: 'Axios',
        category: 'javascript' as TechCategory,
      },
      {
        pattern: /moment[.-](\d+(?:\.\d+)*)/i,
        name: 'Moment.js',
        category: 'javascript' as TechCategory,
      },
      {
        pattern: /three[.-](\d+(?:\.\d+)*)/i,
        name: 'Three.js',
        category: 'javascript' as TechCategory,
      },
      {
        pattern: /d3[.-](\d+(?:\.\d+)*)/i,
        name: 'D3.js',
        category: 'javascript' as TechCategory,
      },
      {
        pattern: /chart[.-](\d+(?:\.\d+)*)/i,
        name: 'Chart.js',
        category: 'javascript' as TechCategory,
      },
      {
        pattern: /gsap[.-](\d+(?:\.\d+)*)/i,
        name: 'GSAP',
        category: 'javascript' as TechCategory,
      },
      {
        pattern: /socket\.io[.-](\d+(?:\.\d+)*)/i,
        name: 'Socket.IO',
        category: 'javascript' as TechCategory,
      },
    ];

    for (const match of scriptSrcs) {
      const src = match[1];
      for (const lib of knownLibraries) {
        const versionMatch = src.match(lib.pattern);
        if (versionMatch) {
          technologies.push({
            name: lib.name,
            category: lib.category,
            version: versionMatch[1],
            confidence: 'high',
            evidence: `Script: ${src.substring(0, 80)}`,
          });
        }
      }
    }
  }

  /**
   * Analyze link tags for CSS frameworks (Medium Confidence)
   */
  private analyzeLinkTags(
    html: string,
    technologies: DetectedTechnology[],
  ): void {
    // Extract all link href attributes for stylesheets
    const linkHrefs = html.matchAll(
      /<link[^>]+(?:rel=["']stylesheet["'][^>]+)?href=["']([^"']+)["'][^>]*>/gi,
    );

    const knownCSS = [
      {
        pattern: /bootstrap[.-](\d+(?:\.\d+)*)/i,
        name: 'Bootstrap',
        category: 'css-framework' as TechCategory,
      },
      {
        pattern: /tailwind(?:css)?[.-](\d+(?:\.\d+)*)/i,
        name: 'Tailwind CSS',
        category: 'css-framework' as TechCategory,
      },
      {
        pattern: /bulma[.-](\d+(?:\.\d+)*)/i,
        name: 'Bulma',
        category: 'css-framework' as TechCategory,
      },
      {
        pattern: /foundation[.-](\d+(?:\.\d+)*)/i,
        name: 'Foundation',
        category: 'css-framework' as TechCategory,
      },
      {
        pattern: /materialize[.-](\d+(?:\.\d+)*)/i,
        name: 'Materialize',
        category: 'css-framework' as TechCategory,
      },
      {
        pattern: /semantic[.-](\d+(?:\.\d+)*)/i,
        name: 'Semantic UI',
        category: 'css-framework' as TechCategory,
      },
      {
        pattern: /fontawesome|font-awesome/i,
        name: 'Font Awesome',
        category: 'css-framework' as TechCategory,
      },
      {
        pattern: /animate\.css/i,
        name: 'Animate.css',
        category: 'css-framework' as TechCategory,
      },
    ];

    for (const match of linkHrefs) {
      const href = match[1];
      for (const lib of knownCSS) {
        const versionMatch = href.match(lib.pattern);
        if (versionMatch) {
          technologies.push({
            name: lib.name,
            category: lib.category,
            version:
              typeof versionMatch[1] === 'string' ? versionMatch[1] : undefined,
            confidence: 'medium',
            evidence: `Stylesheet: ${href.substring(0, 80)}`,
          });
        }
      }
    }
  }

  /**
   * Analyze HTML comments for CMS/framework signatures (Medium Confidence)
   */
  private analyzeHtmlComments(
    html: string,
    technologies: DetectedTechnology[],
  ): void {
    const comments = html.matchAll(/<!--\s*([^>]+?)\s*-->/gi);

    const commentSignatures = [
      {
        pattern: /WordPress/i,
        name: 'WordPress',
        category: 'cms' as TechCategory,
      },
      { pattern: /Joomla!/i, name: 'Joomla', category: 'cms' as TechCategory },
      { pattern: /Drupal/i, name: 'Drupal', category: 'cms' as TechCategory },
      {
        pattern: /This is Squarespace/i,
        name: 'Squarespace',
        category: 'cms' as TechCategory,
      },
      {
        pattern: /Generated by (\w+)/i,
        name: 'CMS',
        category: 'cms' as TechCategory,
      },
      {
        pattern: /Built with (\w+)/i,
        name: 'Framework',
        category: 'framework' as TechCategory,
      },
    ];

    for (const match of comments) {
      const comment = match[1];
      for (const sig of commentSignatures) {
        const sigMatch = comment.match(sig.pattern);
        if (sigMatch) {
          // Use captured group if available
          const name =
            sigMatch[1] && sig.name === 'CMS' ? sigMatch[1] : sig.name;
          technologies.push({
            name,
            category: sig.category,
            confidence: 'medium',
            evidence: `HTML comment: ${comment.substring(0, 50)}`,
          });
        }
      }
    }
  }

  private analyzeHtmlForCms(
    html: string,
    technologies: DetectedTechnology[],
  ): void {
    for (const sig of TECH_SIGNATURES.cms) {
      if (sig.pattern.test(html)) {
        // Use confidenceBoost to determine confidence level
        const confidence = (sig as { confidenceBoost?: boolean })
          .confidenceBoost
          ? 'high'
          : 'medium';
        technologies.push({
          name: sig.name,
          category: sig.category,
          confidence,
          evidence: 'HTML content pattern match',
        });
      }
    }
  }

  private analyzeHtmlForJs(
    html: string,
    technologies: DetectedTechnology[],
  ): void {
    for (const sig of TECH_SIGNATURES.jsFrameworks) {
      if (sig.pattern.test(html)) {
        // Use confidenceBoost to determine confidence level
        const confidence = (sig as { confidenceBoost?: boolean })
          .confidenceBoost
          ? 'high'
          : 'low';
        technologies.push({
          name: sig.name,
          category: sig.category,
          confidence,
          evidence: 'HTML/JavaScript pattern match',
        });
      }
    }
  }

  private analyzeHtmlForAnalytics(
    html: string,
    technologies: DetectedTechnology[],
  ): void {
    for (const sig of TECH_SIGNATURES.analytics) {
      if (sig.pattern.test(html)) {
        // Use confidenceBoost to determine confidence level
        const confidence = (sig as { confidenceBoost?: boolean })
          .confidenceBoost
          ? 'high'
          : 'medium';
        technologies.push({
          name: sig.name,
          category: sig.category,
          confidence,
          evidence: 'Analytics script detected',
        });
      }
    }
  }

  private analyzeCookies(
    headers: Record<string, string>,
    technologies: DetectedTechnology[],
  ): void {
    const setCookie = headers['set-cookie'] || headers['Set-Cookie'] || '';

    if (/PHPSESSID/i.test(setCookie)) {
      technologies.push({
        name: 'PHP',
        category: 'programming-language',
        confidence: 'high',
        evidence: 'PHPSESSID cookie',
      });
    }

    if (/JSESSIONID/i.test(setCookie)) {
      technologies.push({
        name: 'Java',
        category: 'programming-language',
        confidence: 'high',
        evidence: 'JSESSIONID cookie',
      });
    }

    if (/ASP\.NET_SessionId/i.test(setCookie)) {
      technologies.push({
        name: 'ASP.NET',
        category: 'programming-language',
        confidence: 'high',
        evidence: 'ASP.NET_SessionId cookie',
      });
    }

    if (/laravel_session/i.test(setCookie)) {
      technologies.push({
        name: 'Laravel',
        category: 'framework',
        confidence: 'high',
        evidence: 'laravel_session cookie',
      });
    }

    if (/connect\.sid/i.test(setCookie)) {
      technologies.push({
        name: 'Express.js',
        category: 'framework',
        confidence: 'medium',
        evidence: 'connect.sid cookie',
      });
    }

    if (/wp-settings|wordpress/i.test(setCookie)) {
      technologies.push({
        name: 'WordPress',
        category: 'cms',
        confidence: 'high',
        evidence: 'WordPress cookie',
      });
    }

    if (/__cf_bm|cf_clearance/i.test(setCookie)) {
      technologies.push({
        name: 'Cloudflare',
        category: 'cdn',
        confidence: 'high',
        evidence: 'Cloudflare cookie',
      });
    }

    // Django session cookie
    if (/sessionid|csrftoken/i.test(setCookie) && /django/i.test(setCookie)) {
      technologies.push({
        name: 'Django',
        category: 'framework',
        confidence: 'high',
        evidence: 'Django session cookie',
      });
    }

    // Rails session cookie
    if (/_session/i.test(setCookie) && /rails|rack/i.test(setCookie)) {
      technologies.push({
        name: 'Ruby on Rails',
        category: 'framework',
        confidence: 'high',
        evidence: 'Rails session cookie',
      });
    }
  }

  /**
   * Enhanced deduplication that boosts confidence when multiple evidence sources are found.
   * This reduces false positives by requiring corroborating evidence for uncertain detections.
   */
  private deduplicateAndBoostConfidence(
    technologies: DetectedTechnology[],
  ): DetectedTechnology[] {
    const grouped = new Map<string, DetectedTechnology[]>();

    // Group by technology name and category
    for (const tech of technologies) {
      const key = `${tech.name.toLowerCase()}-${tech.category}`;
      const list = grouped.get(key) || [];
      list.push(tech);
      grouped.set(key, list);
    }

    const result: DetectedTechnology[] = [];

    for (const [, techs] of grouped) {
      if (techs.length === 0) continue;

      // Collect all unique evidence sources
      const evidenceSources = new Set(techs.map((t) => t.evidence));

      // Find the best version if any
      const versions = techs.filter((t) => t.version).map((t) => t.version!);
      const bestVersion = versions.length > 0 ? versions[0] : undefined;

      // Determine confidence based on evidence count and existing confidence levels
      let finalConfidence: 'high' | 'medium' | 'low';
      const hasHighConfidence = techs.some((t) => t.confidence === 'high');
      const hasMediumConfidence = techs.some((t) => t.confidence === 'medium');

      if (hasHighConfidence) {
        finalConfidence = 'high';
      } else if (evidenceSources.size >= 2 || hasMediumConfidence) {
        // Multiple evidence sources boost low to medium
        finalConfidence = evidenceSources.size >= 3 ? 'high' : 'medium';
      } else {
        finalConfidence = 'low';
      }

      // Combine evidence (up to 3 sources)
      const combinedEvidence = Array.from(evidenceSources)
        .slice(0, 3)
        .join(' | ');

      result.push({
        name: techs[0].name,
        category: techs[0].category,
        version: bestVersion,
        confidence: finalConfidence,
        evidence: combinedEvidence,
      });
    }

    // Sort by confidence (high first) then by name
    return result.sort((a, b) => {
      const confidenceOrder = { high: 0, medium: 1, low: 2 };
      const confDiff =
        confidenceOrder[a.confidence] - confidenceOrder[b.confidence];
      if (confDiff !== 0) return confDiff;
      return a.name.localeCompare(b.name);
    });
  }

  private formatResults(
    url: string,
    technologies: DetectedTechnology[],
    securityFindings: string[],
    headers: Record<string, string>,
    includeHeaders: boolean,
    statusCode: number,
  ): ToolResult {
    // Group by category
    const byCategory = new Map<TechCategory, DetectedTechnology[]>();
    for (const tech of technologies) {
      const list = byCategory.get(tech.category) || [];
      list.push(tech);
      byCategory.set(tech.category, list);
    }

    const categoryOrder: TechCategory[] = [
      'web-server',
      'cdn',
      'waf',
      'programming-language',
      'framework',
      'cms',
      'e-commerce',
      'javascript',
      'css-framework',
      'analytics',
      'security',
      'cache',
      'hosting',
      'database',
      'other',
    ];

    const categoryNames: Record<TechCategory, string> = {
      'web-server': '🖥️ Web Server',
      cdn: '🌐 CDN',
      waf: '🛡️ WAF/Security',
      'programming-language': '💻 Programming Language',
      framework: '🏗️ Framework',
      cms: '📝 CMS',
      'e-commerce': '🛒 E-Commerce',
      javascript: '📜 JavaScript',
      'css-framework': '🎨 CSS Framework',
      analytics: '📊 Analytics',
      security: '🔒 Security Headers',
      cache: '⚡ Cache',
      hosting: '☁️ Hosting',
      database: '🗄️ Database',
      other: '📦 Other',
    };

    const output: string[] = [
      `# Web Technology Analysis: ${url}`,
      '',
      `**HTTP Status:** ${statusCode}`,
      `**Technologies Detected:** ${technologies.length}`,
      '',
    ];

    for (const category of categoryOrder) {
      const techs = byCategory.get(category);
      if (!techs || techs.length === 0) continue;

      output.push(`## ${categoryNames[category]}`);
      for (const tech of techs) {
        const version = tech.version ? ` v${tech.version}` : '';
        const confidence =
          tech.confidence === 'high'
            ? '✅'
            : tech.confidence === 'medium'
              ? '🔸'
              : '⚪';
        output.push(`- ${confidence} **${tech.name}**${version}`);
        output.push(`  - Evidence: ${tech.evidence}`);
      }
      output.push('');
    }

    // Security findings
    if (securityFindings.length > 0) {
      output.push('## ⚠️ Security Findings');
      for (const finding of securityFindings) {
        output.push(`- ${finding}`);
      }
      output.push('');
    }

    // Include headers if requested
    if (includeHeaders) {
      output.push('## 📋 HTTP Response Headers');
      output.push('```');
      for (const [key, value] of Object.entries(headers)) {
        output.push(`${key}: ${value}`);
      }
      output.push('```');
      output.push('');
    }

    output.push('---');
    output.push(
      '*Legend: ✅ High confidence | 🔸 Medium confidence | ⚪ Low confidence*',
    );

    // Add CVE intelligence recommendations
    // 🔒 MEMORY OPTIMIZATION: Deduplicate and limit products
    const seenProducts = new Set<string>();
    const MAX_PRODUCTS = 15;
    const detectedProducts: DetectedProduct[] = [];

    for (const t of technologies) {
      if (detectedProducts.length >= MAX_PRODUCTS) break;
      if (
        t.version &&
        (t.category === 'web-server' ||
          t.category === 'framework' ||
          t.category === 'cms' ||
          t.category === 'programming-language')
      ) {
        const productKey = `${t.name}:${t.version}`.toLowerCase();
        if (!seenProducts.has(productKey)) {
          seenProducts.add(productKey);
          detectedProducts.push({
            name: t.name,
            version: t.version,
            vendor: t.name.toLowerCase(),
            confidence: t.confidence,
            source: `${categoryNames[t.category]} detection`,
          });
        }
      }
    }

    if (detectedProducts.length > 0) {
      output.push('\n');
      output.push(formatCVEIntelligenceSection(detectedProducts, true));
    }

    const summary = output.join('\n');

    return {
      llmContent: summary,
      returnDisplay: summary,
    };
  }
}

/**
 * Web Technology Detection Tool
 *
 * Detects web technologies by analyzing HTTP headers, HTML content,
 * JavaScript/CSS patterns, and cookies. No API key required.
 */
export class WebTechTool extends BaseDeclarativeTool<
  WebTechToolParams,
  ToolResult
> {
  static readonly Name = ToolNames.WEB_TECH;

  constructor(_config: Config) {
    super(
      WebTechTool.Name,
      ToolDisplayNames.WEB_TECH,
      `Detect web technologies used by a website. Analyzes HTTP headers, HTML patterns, JavaScript frameworks, CSS frameworks, CMS, CDN, WAF, analytics, and security headers. NO API KEY REQUIRED - completely free.

Use this when you need to:
- Identify what technologies a website uses
- Detect CMS (WordPress, Drupal, etc.)
- Find JavaScript frameworks (React, Vue, Angular)
- Identify web servers (nginx, Apache, IIS)
- Detect CDN/WAF (Cloudflare, Akamai, etc.)
- Check security headers
- Find analytics tools (Google Analytics, etc.)

This is a FREE alternative to Censys for web technology fingerprinting.`,
      Kind.Fetch,
      {
        properties: {
          url: {
            type: 'string',
            description:
              'The URL to analyze for web technologies. Can be with or without https:// prefix.',
          },
          includeHeaders: {
            type: 'boolean',
            description: 'Include full HTTP response headers in output',
          },
          followRedirects: {
            type: 'boolean',
            description: 'Whether to follow HTTP redirects (default: true)',
          },
        },
        required: ['url'],
        type: 'object',
      },
    );
  }

  protected createInvocation(
    params: WebTechToolParams,
  ): ToolInvocation<WebTechToolParams, ToolResult> {
    return new WebTechToolInvocation(params);
  }
}
