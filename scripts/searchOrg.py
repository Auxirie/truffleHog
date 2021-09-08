"""
Credit for this code goes to https://github.com/ryanbaxendale 
via https://github.com/dxa4481/truffleHog/pull/9
"""
import requests
from truffleHog import truffleHog
import re
from json import loads, dumps

rules = {
    "Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (OPENSSH) private key": "-----BEGIN OPENSSH PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Facebook Oauth": "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]",
    "Twitter Oauth": "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]",
    "GitHub": "[g|G][i|I][t|T][h|H][u|U][b|B].{0,30}['\"\\s][0-9a-zA-Z]{35,40}['\"\\s]",
    "Google Oauth": "(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")",
    "AWS API Key": "AKIA[0-9A-Z]{16}",
    "Heroku API Key": "[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Generic Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]",
    "Generic API Key": "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]",
    "Slack Webhook": "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Google (GCP) Service-account": "\"type\": \"service_account\"",
    "Twilio API Key": "SK[a-z0-9]{32}",
    "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
    "SlackInternal": "slack-corp",
    "Vault Token": "[sb]\.[a-zA-Z0-9]{24}",
    "Stripe API Key": "(?:r|s)k_live_[0-9a-zA-Z]{24}",
    "Square Access Token": "sqOatp-[0-9A-Za-z\\-_]{22}",
    "Square Oauth Secret": "sq0csp-[ 0-9A-Za-z\\-_]{43}",
    "Picatic API Key": "sk_live_[0-9a-z]{32}",
    "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
    "Mailchamp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
    "IPv4": "\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b",
    "Artifactory API Token": "(?:\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}",
    "Artifactory Password": "(?:\s|=|:|\"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}",
    "Authorization Basic": "basic [a-zA-Z0-9_\\-:\\.=]+",
    "Authorization Bearer": "bearer [a-zA-Z0-9_\\-\\.=]+",
    "AWS Client ID": "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS MWS Key": "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS Secret Key": "(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]",
    "Shopify private app access token": "shppa_[a-fA-F0-9]{32}",
    "PyPI upload token": "pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,1000}",
    "Shopify custom app access token": "shpca_[a-fA-F0-9]{32}",
    "Shopify access token": "shpat_[a-fA-F0-9]{32}",
    "Shopify shared secret": "shpss_[a-fA-F0-9]{32}",
    "Dynatrace token": "dt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}",
    "SendGrid API Key": "SG\.[\w_]{16,32}\.[\w_]{16,64}",
    "Picatic API key": "sk_live_[0-9a-z]{32}",
    "PayPal Braintree access token": "access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Google API key": "AIza[0-9A-Za-z\\-_]{35}",
    "Github Refresh Token": "ghr_[0-9a-zA-Z]{76}",
    "Github App Token": "(ghu|ghs)_[0-9a-zA-Z]{36}",
    "Github OAuth Access Token": "gho_[0-9a-zA-Z]{36}",
    "Github Personal Access Token": "ghp_[0-9a-zA-Z]{36}",
    "NPM Token": "[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}",
}

for key in rules:
    rules[key] = re.compile(rules[key])

def get_org_repos(orgname, page):
    response = requests.get(url='https://api.github.com/users/' + orgname + '/repos?page={}'.format(page))
    json = response.json()
    if not json:
        return None
    for item in json:

        if item['fork'] == False:
            print('searching ' + item["html_url"])
            results = truffleHog.find_strings(item["html_url"], do_regex=True, custom_regexes=rules, do_entropy=False, max_depth=100000)
            for issue in results["foundIssues"]:
                d = loads(open(issue).read())
                d['github_url'] = "{}/blob/{}/{}".format(item["html_url"], d['commitHash'], d['path'])
                d['github_commit_url'] = "{}/commit/{}".format(item["html_url"], d['commitHash'])
                d['diff'] = d['diff'][0:200]
                d['printDiff'] = d['printDiff'][0:200]
                print(dumps(d, indent=4))
    get_org_repos(orgname, page + 1)
get_org_repos("Twitter", 1)
