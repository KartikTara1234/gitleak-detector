// Detection rules. Each rule has:
//   id        - stable identifier
//   name      - human label
//   provider  - used to build the rotation checklist
//   severity  - critical | high | medium | low
//   regex     - must have the 'g' flag; group 1 (if present) is the secret itself
//   verify    - optional extra check on the matched string to cut false positives
//
// Keep patterns specific. A rule that fires on every hex string is worse than no rule.

export const RULES = [
  // ---- Cloud providers ----
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    provider: 'aws',
    severity: 'critical',
    regex: /\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16})\b/g,
  },
  {
    id: 'aws-secret-key',
    name: 'AWS Secret Access Key',
    provider: 'aws',
    severity: 'critical',
    regex: /aws[_\-\s]?(?:secret)?[_\-\s]?(?:access)?[_\-\s]?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
  },
  {
    id: 'gcp-api-key',
    name: 'Google API Key',
    provider: 'google',
    severity: 'high',
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
  },
  {
    id: 'gcp-service-account',
    name: 'Google Service Account JSON',
    provider: 'google',
    severity: 'critical',
    regex: /"type"\s*:\s*"service_account"/g,
  },
  {
    id: 'azure-storage-key',
    name: 'Azure Storage Account Key',
    provider: 'azure',
    severity: 'critical',
    regex: /AccountKey=([A-Za-z0-9+/=]{88})/g,
  },

  // ---- Source control / CI ----
  {
    id: 'github-token',
    name: 'GitHub Personal Access Token',
    provider: 'github',
    severity: 'critical',
    regex: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b/g,
  },
  {
    id: 'github-fine-grained',
    name: 'GitHub Fine-grained Token',
    provider: 'github',
    severity: 'critical',
    regex: /\b(github_pat_[A-Za-z0-9_]{22,})\b/g,
  },
  {
    id: 'gitlab-token',
    name: 'GitLab Personal Access Token',
    provider: 'gitlab',
    severity: 'critical',
    regex: /\b(glpat-[A-Za-z0-9\-_]{20,})\b/g,
  },
  {
    id: 'npm-token',
    name: 'npm Access Token',
    provider: 'npm',
    severity: 'high',
    regex: /\b(npm_[A-Za-z0-9]{36})\b/g,
  },

  // ---- Payments ----
  {
    id: 'stripe-live-secret',
    name: 'Stripe Live Secret Key',
    provider: 'stripe',
    severity: 'critical',
    regex: /\b(sk_live_[0-9a-zA-Z]{24,})\b/g,
  },
  {
    id: 'stripe-test-secret',
    name: 'Stripe Test Secret Key',
    provider: 'stripe',
    severity: 'medium',
    regex: /\b(sk_test_[0-9a-zA-Z]{24,})\b/g,
  },
  {
    id: 'razorpay-key',
    name: 'Razorpay Key ID',
    provider: 'razorpay',
    severity: 'high',
    regex: /\b(rzp_(?:live|test)_[A-Za-z0-9]{14,})\b/g,
  },

  // ---- Messaging / comms ----
  {
    id: 'slack-token',
    name: 'Slack Token',
    provider: 'slack',
    severity: 'critical',
    regex: /\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b/g,
  },
  {
    id: 'slack-webhook',
    name: 'Slack Incoming Webhook',
    provider: 'slack',
    severity: 'high',
    regex: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+)/g,
  },
  {
    id: 'discord-webhook',
    name: 'Discord Webhook',
    provider: 'discord',
    severity: 'high',
    regex: /(https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]+)/g,
  },
  {
    id: 'twilio-api-key',
    name: 'Twilio API Key',
    provider: 'twilio',
    severity: 'high',
    regex: /\b(SK[0-9a-fA-F]{32})\b/g,
  },
  {
    id: 'sendgrid-key',
    name: 'SendGrid API Key',
    provider: 'sendgrid',
    severity: 'high',
    regex: /\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b/g,
  },
  {
    id: 'telegram-bot-token',
    name: 'Telegram Bot Token',
    provider: 'telegram',
    severity: 'high',
    regex: /\b(\d{8,10}:AA[A-Za-z0-9_\-]{33})\b/g,
  },

  // ---- AI providers ----
  {
    id: 'openai-key',
    name: 'OpenAI API Key',
    provider: 'openai',
    severity: 'critical',
    regex: /\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})\b/g,
    verify: (s) => !s.startsWith('sk-ant-'),
  },
  {
    id: 'anthropic-key',
    name: 'Anthropic API Key',
    provider: 'anthropic',
    severity: 'critical',
    regex: /\b(sk-ant-[A-Za-z0-9_\-]{32,})\b/g,
  },
  {
    id: 'huggingface-token',
    name: 'Hugging Face Token',
    provider: 'huggingface',
    severity: 'high',
    regex: /\b(hf_[A-Za-z0-9]{34,})\b/g,
  },

  // ---- Databases / connection strings ----
  {
    id: 'mongodb-uri',
    name: 'MongoDB Connection String with Credentials',
    provider: 'mongodb',
    severity: 'critical',
    regex: /(mongodb(?:\+srv)?:\/\/[^\s:/'"]+:[^\s@'"]+@[^\s'"]+)/g,
  },
  {
    id: 'postgres-uri',
    name: 'PostgreSQL Connection String with Credentials',
    provider: 'postgres',
    severity: 'critical',
    regex: /(postgres(?:ql)?:\/\/[^\s:/'"]+:[^\s@'"]+@[^\s'"]+)/g,
  },
  {
    id: 'mysql-uri',
    name: 'MySQL Connection String with Credentials',
    provider: 'mysql',
    severity: 'critical',
    regex: /(mysql:\/\/[^\s:/'"]+:[^\s@'"]+@[^\s'"]+)/g,
  },
  {
    id: 'redis-uri',
    name: 'Redis Connection String with Credentials',
    provider: 'redis',
    severity: 'high',
    regex: /(redis(?:s)?:\/\/[^\s:/'"]*:[^\s@'"]+@[^\s'"]+)/g,
  },

  // ---- Keys & certs ----
  {
    id: 'private-key',
    name: 'Private Key Block',
    provider: 'private-key',
    severity: 'critical',
    regex: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)/g,
  },
  {
    id: 'jwt',
    name: 'JSON Web Token',
    provider: 'jwt',
    severity: 'medium',
    regex: /\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b/g,
  },

  // ---- Generic assignments (lower confidence) ----
  {
    id: 'generic-password',
    name: 'Hardcoded Password',
    provider: 'generic',
    severity: 'high',
    regex: /\b(?:password|passwd|pwd|db_pass|database_password)\s*[:=]\s*["']([^"'\s]{8,})["']/gi,
  },
  {
    id: 'generic-secret',
    name: 'Hardcoded Secret / Token',
    provider: 'generic',
    severity: 'medium',
    regex: /\b(?:secret|token|api[_\-]?key|apikey|auth[_\-]?token|access[_\-]?token|client[_\-]?secret|private[_\-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-/+=.]{16,})["']/gi,
  },
  {
    id: 'basic-auth-url',
    name: 'URL with Embedded Credentials',
    provider: 'generic',
    severity: 'high',
    regex: /\b(https?:\/\/[A-Za-z0-9._%+\-]+:[^\s@'"/]{3,}@[A-Za-z0-9.\-]+)/g,
  },
];

// Files that should never be committed, matched against the path relative to repo root.
export const SENSITIVE_FILES = [
  { pattern: /(^|\/)\.env(\..+)?$/i, name: 'Committed .env file', severity: 'critical', provider: 'env-file',
    exclude: /\.(example|sample|template|dist)$/i },
  { pattern: /\.(pem|key|p12|pfx|jks|keystore)$/i, name: 'Committed private key / certificate file', severity: 'critical', provider: 'private-key' },
  { pattern: /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/i, name: 'Committed SSH private key', severity: 'critical', provider: 'private-key' },
  { pattern: /(^|\/)\.npmrc$/i, name: 'Committed .npmrc (may contain auth token)', severity: 'medium', provider: 'npm' },
  { pattern: /(^|\/)\.pypirc$/i, name: 'Committed .pypirc (may contain credentials)', severity: 'medium', provider: 'generic' },
  { pattern: /(^|\/)\.netrc$/i, name: 'Committed .netrc (contains credentials)', severity: 'high', provider: 'generic' },
  { pattern: /(^|\/)\.(aws|azure|gcloud)\/credentials$/i, name: 'Committed cloud CLI credentials', severity: 'critical', provider: 'aws' },
  { pattern: /(^|\/)(credentials|secrets?)\.(json|ya?ml|toml)$/i, name: 'Committed credentials/secrets config file', severity: 'high', provider: 'generic' },
  { pattern: /(^|\/)firebase-adminsdk[^/]*\.json$/i, name: 'Committed Firebase admin SDK key', severity: 'critical', provider: 'google' },
];

// Tokens that strongly suggest a placeholder, not a real secret.
export const PLACEHOLDER_HINTS = [
  'example', 'placeholder', 'your_', 'your-', 'yourkey', 'changeme', 'change_me', 'xxxx', '****',
  'dummy', 'fake', 'sample', 'test123', 'password123', '<your', 'insert', 'redacted', 'todo',
  'replace', 'abc123', '000000', '123456', 'secret_here', 'key_here', 'token_here',
];

export const SEVERITY_WEIGHT = { critical: 25, high: 12, medium: 5, low: 1 };

export const ROTATION_STEPS = {
  aws: {
    label: 'AWS',
    steps: [
      'Open IAM → Users → Security credentials and deactivate, then delete, the exposed access key.',
      'Create a new key pair and update it in your secrets manager / CI variables.',
      'Check CloudTrail for unexpected activity since the commit date.',
    ],
    docs: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
  },
  google: {
    label: 'Google Cloud',
    steps: [
      'In Google Cloud Console → APIs & Services → Credentials, delete the exposed key or service account key.',
      'Generate a replacement and restrict it by API and by referrer/IP.',
      'Review billing and audit logs for abuse.',
    ],
    docs: 'https://cloud.google.com/docs/authentication/api-keys',
  },
  azure: {
    label: 'Azure',
    steps: [
      'Regenerate the storage account key (key1/key2) in the Azure portal.',
      'Update every app and pipeline that used the old key.',
    ],
    docs: 'https://learn.microsoft.com/azure/storage/common/storage-account-keys-manage',
  },
  github: {
    label: 'GitHub',
    steps: [
      'GitHub → Settings → Developer settings → Personal access tokens → revoke the token.',
      'Create a fine-grained token with the minimum repositories and permissions.',
      'Note: GitHub often auto-revokes leaked PATs it detects in public repos, but do not rely on that.',
    ],
    docs: 'https://docs.github.com/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens',
  },
  gitlab: {
    label: 'GitLab',
    steps: ['Revoke the token under User Settings → Access Tokens and issue a new scoped token.'],
    docs: 'https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html',
  },
  npm: {
    label: 'npm',
    steps: ['Run `npm token revoke <id>` or revoke from npmjs.com → Access Tokens, then create a new granular token.'],
    docs: 'https://docs.npmjs.com/revoking-access-tokens',
  },
  stripe: {
    label: 'Stripe',
    steps: [
      'Stripe Dashboard → Developers → API keys → roll the secret key (the old one stops working immediately or after the grace period you choose).',
      'Check the Logs tab for unknown requests.',
    ],
    docs: 'https://docs.stripe.com/keys#rolling-keys',
  },
  razorpay: {
    label: 'Razorpay',
    steps: ['Razorpay Dashboard → Settings → API Keys → regenerate.'],
    docs: 'https://razorpay.com/docs/api/authentication/',
  },
  slack: {
    label: 'Slack',
    steps: [
      'Revoke the token from the app settings (OAuth & Permissions) or regenerate the webhook URL.',
      'Reinstall the app to the workspace to get fresh credentials.',
    ],
    docs: 'https://api.slack.com/authentication/best-practices',
  },
  discord: {
    label: 'Discord',
    steps: ['Delete the webhook in Server Settings → Integrations → Webhooks and create a new one.'],
    docs: 'https://support.discord.com/hc/articles/228383668',
  },
  twilio: {
    label: 'Twilio',
    steps: ['Twilio Console → Account → API keys & tokens → delete the key; rotate the auth token if it was also exposed.'],
    docs: 'https://www.twilio.com/docs/iam/api-keys',
  },
  sendgrid: {
    label: 'SendGrid',
    steps: ['SendGrid → Settings → API Keys → delete the key and create a restricted one.'],
    docs: 'https://docs.sendgrid.com/ui/account-and-settings/api-keys',
  },
  telegram: {
    label: 'Telegram',
    steps: ['Message @BotFather → /revoke to invalidate the bot token and get a new one.'],
    docs: 'https://core.telegram.org/bots/features#botfather',
  },
  openai: {
    label: 'OpenAI',
    steps: ['platform.openai.com → API keys → delete the exposed key and create a new one with a project scope.', 'Check usage for unexpected spend.'],
    docs: 'https://platform.openai.com/api-keys',
  },
  anthropic: {
    label: 'Anthropic',
    steps: ['console.anthropic.com → API Keys → disable the key and create a new one.', 'Check usage for unexpected spend.'],
    docs: 'https://console.anthropic.com/settings/keys',
  },
  huggingface: {
    label: 'Hugging Face',
    steps: ['huggingface.co/settings/tokens → invalidate and refresh.'],
    docs: 'https://huggingface.co/docs/hub/security-tokens',
  },
  mongodb: {
    label: 'MongoDB',
    steps: [
      'In Atlas (or your DB), change the password for that database user — or delete the user and create a new one.',
      'Tighten the IP access list; a public repo leak means assume the IP list was also probed.',
    ],
    docs: 'https://www.mongodb.com/docs/atlas/security-add-mongodb-users/',
  },
  postgres: {
    label: 'PostgreSQL',
    steps: ['Run `ALTER USER <name> WITH PASSWORD \'<new>\';` and update the connection string wherever it is used.'],
    docs: 'https://www.postgresql.org/docs/current/sql-alteruser.html',
  },
  mysql: {
    label: 'MySQL',
    steps: ['Run `ALTER USER \'<name>\'@\'%\' IDENTIFIED BY \'<new>\';` and update connection strings.'],
    docs: 'https://dev.mysql.com/doc/refman/8.0/en/alter-user.html',
  },
  redis: {
    label: 'Redis',
    steps: ['Change `requirepass` / ACL user password and restart or `CONFIG SET`.'],
    docs: 'https://redis.io/docs/management/security/acl/',
  },
  'private-key': {
    label: 'Private keys / certificates',
    steps: [
      'Treat the key as compromised: generate a new key pair and replace it wherever the public half is registered (servers, GitHub deploy keys, TLS).',
      'Revoke any certificate issued against the leaked key.',
    ],
    docs: 'https://docs.github.com/authentication/connecting-to-github-with-ssh',
  },
  jwt: {
    label: 'JWT',
    steps: ['If this is a long-lived token, rotate the signing secret so every issued token is invalidated.'],
    docs: 'https://jwt.io/introduction',
  },
  'env-file': {
    label: '.env file',
    steps: [
      'Every value inside the committed .env must be rotated — treat each one as leaked.',
      'Remove the file from git history (git filter-repo or BFG), not just from the latest commit.',
      'Add `.env*` to .gitignore and commit a `.env.example` with blank values instead.',
    ],
    docs: 'https://docs.github.com/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository',
  },
  generic: {
    label: 'Other credentials',
    steps: [
      'Change the password / regenerate the token at the service that issued it.',
      'Move the value into an environment variable and load it with dotenv (or your platform\'s secrets store).',
    ],
    docs: 'https://12factor.net/config',
  },
};
