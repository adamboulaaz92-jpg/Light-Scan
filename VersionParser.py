import re

class VersionParser:
    """Extract version information from banners"""

    @staticmethod
    def parse_version(banner, port):
        """Main version parsing method"""
        if not banner:
            return None

        if port == 22:
            version_info = VersionParser._parse_ssh(banner)
        elif port == 80 or port == 443 or port == 8080 or port == 8443:
            version_info = VersionParser._parse_http(banner)
        elif port == 21:
            version_info = VersionParser._parse_ftp(banner)
        elif port == 25 or port == 587 or port == 465:
            version_info = VersionParser._parse_smtp(banner)
        elif port == 3306:
            version_info = VersionParser._parse_mysql(banner)
        elif port == 5432:
            version_info = VersionParser._parse_postgresql(banner)
        elif port == 6379:
            version_info = VersionParser._parse_redis(banner)
        elif port == 1433:
            version_info = VersionParser._parse_mssql(banner)
        elif port == 27017:
            version_info = VersionParser._parse_mongodb(banner)
        elif port == 9200:
            version_info = VersionParser._parse_elasticsearch(banner)
        elif port == 110 or port == 995:
            version_info = VersionParser._parse_pop3(banner)
        elif port == 143 or port == 993:
            version_info = VersionParser._parse_imap(banner)
        elif port == 3389:
            version_info = VersionParser._parse_rdp(banner)
        elif port == 5900:
            version_info = VersionParser._parse_vnc(banner)
        elif port == 139 or port == 445:
            version_info = VersionParser._parse_smb(banner)
        else:
            version_info = VersionParser._parse_generic(banner)

        return version_info

    @staticmethod
    def _parse_ssh(banner):
        patterns = [
            r'SSH-(\d+\.\d+)-([\w]+)[_-](\d+\.\d+[^\s]*)',
            r'SSH-(\d+\.\d+)-([\w]+)\s+([\d.]+)',
            r'SSH-(\d+\.\d+)-([\w]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, banner)
            if match:
                if len(match.groups()) == 3:
                    return {
                        'service': 'ssh',
                        'protocol': match.group(1),
                        'product': match.group(2),
                        'version': match.group(3)
                    }
                elif len(match.groups()) == 2:
                    return {
                        'service': 'ssh',
                        'protocol': match.group(1),
                        'product': match.group(2),
                        'version': 'unknown'
                    }
        return None

    @staticmethod
    def _parse_http(banner):
        if "Microsoft-HTTPAPI/2.0" in banner:
            return {
                'service': 'http',
                'product': "Microsoft-HTTPAPI",
                'version': '2.0',
            }

        patterns = [
            r'Server: \s*([\w]+)',
            r'Server:\s*([\w]+)/([\d.]+)',
            r'Server:\s*([\w]+)\s+([\d.]+)',
            r'Server:\s*([\w\-]+)/([\d.]+)(?:\s+\(([^)]+)\))?',
            r'X-Powered-By:\s*([\w]+)/([\d.]+)',
            r'X-Powered-By:\s*([\w\-]+)\s+([\d.]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                if len(match.groups()) >= 2:
                    version_info = {
                        'service': 'http',
                        'product': match.group(1),
                        'version': match.group(2)
                    }
                    if len(match.groups()) == 3:
                        version_info['os'] = match.group(3)
                    return version_info

        frameworks = {
            r'X-Powered-By:\s*PHP': 'php',
            r'X-Powered-By:\s*ASP\.NET': 'asp.net',
            r'X-Generator:\s*WordPress': 'wordpress',
            r'X-Generator:\s*Drupal': 'drupal',
            r'X-Generator:\s*Joomla': 'joomla',
            r'X-Generator:\s*Laravel': 'laravel',
            r'X-Generator:\s*Django': 'django',
            r'X-Generator:\s*Ruby on Rails': 'rails',
            r'X-Generator:\s*Node\.js': 'nodejs',
            r'X-Generator:\s*Express': 'express',
            r'X-Generator:\s*Flask': 'flask',
        }

        for pattern, product in frameworks.items():
            if re.search(pattern, banner, re.IGNORECASE):
                return {
                    'service': 'http',
                    'product': product,
                    'version': 'unknown',
                    'framework': True
                }

        return None

    @staticmethod
    def _parse_ftp(banner):
        patterns = [
            r'([\w]+)[\s-]+([\d.]+)',
            r'([\w]+)\/([\d.]+)',
            r'220\s+([\w]+)\s+([\d.]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, banner)
            if match:
                return {
                    'service': 'ftp',
                    'product': match.group(1),
                    'version': match.group(2)
                }
        return None

    @staticmethod
    def _parse_smtp(banner):
        patterns = [
            r'ESMTP\s+([\w]+)\s+\(([^)]+)\)',
            r'ESMTP\s+([\w]+)[\s-]+([\d.]+)',
            r'220.*ESMTP\s+([\w]+)\s+([\d.]+)',
            r'220.*ESMTP\s+([\w\-]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                if len(match.groups()) == 2:
                    return {
                        'service': 'smtp',
                        'product': match.group(1),
                        'version': match.group(2) if match.group(2) != 'Ubuntu' else 'unknown'
                    }
                elif len(match.groups()) == 1:
                    return {
                        'service': 'smtp',
                        'product': match.group(1),
                        'version': 'unknown'
                    }
        return None

    @staticmethod
    def _parse_mysql(banner):
        match = re.search(r'[\d.]+(?:-[\w.]+)?', banner)
        if match:
            version = match.group(0)
            return {
                'service': 'mysql',
                'product': 'MySQL',
                'version': version
            }
        return None

    @staticmethod
    def _parse_postgresql(banner):
        match = re.search(r'PostgreSQL\s+([\d.]+)', banner, re.IGNORECASE)
        if match:
            return {
                'service': 'postgresql',
                'product': 'PostgreSQL',
                'version': match.group(1)
            }
        return None

    @staticmethod
    def _parse_redis(banner):
        match = re.search(r'v=([\d.]+)', banner)
        if match:
            return {
                'service': 'redis',
                'product': 'Redis',
                'version': match.group(1)
            }
        return None

    @staticmethod
    def _parse_mssql(banner):
        match = re.search(r'Microsoft SQL Server (\d{4})', banner, re.IGNORECASE)
        if match:
            return {
                'service': 'mssql',
                'product': 'Microsoft SQL Server',
                'version': match.group(1)
            }
        return None

    @staticmethod
    def _parse_mongodb(banner):
        match = re.search(r'([\d.]+)', banner)
        if match:
            return {
                'service': 'mongodb',
                'product': 'MongoDB',
                'version': match.group(1)
            }
        return None

    @staticmethod
    def _parse_elasticsearch(banner):
        match = re.search(r'"number"\s*:\s*"([\d.]+)"', banner)
        if match:
            return {
                'service': 'elasticsearch',
                'product': 'Elasticsearch',
                'version': match.group(1)
            }
        return None

    @staticmethod
    def _parse_pop3(banner):
        patterns = [
            r'POP3\s+([\w]+)\s+([\d.]+)',
            r'\+OK\s+([\w]+)\s+([\d.]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return {
                    'service': 'pop3',
                    'product': match.group(1),
                    'version': match.group(2)
                }
        return None

    @staticmethod
    def _parse_imap(banner):
        patterns = [
            r'IMAP\s+([\w]+)\s+([\d.]+)',
            r'\* OK\s+([\w]+)\s+([\d.]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return {
                    'service': 'imap',
                    'product': match.group(1),
                    'version': match.group(2)
                }
        return None

    @staticmethod
    def _parse_rdp(banner):
        patterns = [
            r'Windows\s+(\d+)',
            r'Windows\s+(?:Server\s+)?(\d{4})',
        ]
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return {
                    'service': 'rdp',
                    'product': 'Windows',
                    'version': match.group(1)
                }
        return None

    @staticmethod
    def _parse_vnc(banner):
        match = re.search(r'RFB\s+([\d.]+)', banner, re.IGNORECASE)
        if match:
            return {
                'service': 'vnc',
                'product': 'VNC',
                'version': match.group(1)
            }
        return None

    @staticmethod
    def _parse_smb(banner):
        match = re.search(r'SMB\s+([\d.]+)', banner, re.IGNORECASE)
        if match:
            return {
                'service': 'smb',
                'product': 'SMB',
                'version': match.group(1)
            }
        return None

    @staticmethod
    def _parse_generic(banner):
        patterns = [
            r'v([\d.]+)',
            r'version\s+([\d.]+)',
            r'([\d]+\.[\d]+\.[\d]+)',
            r'([\d]+\.[\d]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                product_match = re.search(r'^([A-Za-z]+)', banner)
                product = product_match.group(1) if product_match else 'unknown'

                return {
                    'service': 'unknown',
                    'product': product,
                    'version': match.group(1)
                }
        return None