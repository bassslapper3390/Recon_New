import asyncio
import shutil
import subprocess
import json
import re
from typing import List, Optional, Tuple, Dict, Any

async def run_command(cmd: List[str], timeout: int = 120) -> Tuple[bool, str]:
	try:
		proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
		try:
			stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
			exit_code = proc.returncode
			return (exit_code == 0, stdout.decode(errors='ignore'))
		except asyncio.TimeoutError:
			proc.kill()
			return (False, f"Timeout after {timeout}s: {' '.join(cmd)}")
	except FileNotFoundError:
		# Try WSL fallback
		wsl = shutil.which('wsl') or shutil.which('wsl.exe')
		if wsl:
			bash_cmd = ' '.join(cmd)
			try:
				proc = await asyncio.create_subprocess_exec(wsl, 'bash', '-lc', bash_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
				stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
				return (proc.returncode == 0, stdout.decode(errors='ignore'))
			except Exception as e:
				return (False, f"WSL fallback failed: {e}")
		return (False, f"Command not found: {cmd[0]}")

async def which(name: str) -> Optional[str]:
	# Try PATH
	p = shutil.which(name)
	if p:
		return p
	# Try common install locations
	from app.services.tools import resolve_executable
	return await resolve_executable(name)

# Core tools
async def nmap_scan(target: str) -> Tuple[bool, str]:
	"""Simple port scanning using Python (alternative to nmap)"""
	try:
		import socket
		
		# Common ports to scan
		common_ports = [21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 161, 389, 443, 445, 465, 587, 993, 995, 1433, 1521, 1723, 2375, 2376, 27017, 3306, 3389, 5432, 5900, 6379, 8000, 8008, 8080, 8443]
		
		open_ports = []
		for port in common_ports:
			try:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(1)
				result = sock.connect_ex((target, port))
				if result == 0:
					# Try to get service name
					try:
						service = socket.getservbyport(port)
					except:
						service = "unknown"
					open_ports.append(f"{port} ({service})")
				sock.close()
			except:
				continue
		
		if open_ports:
			result = f"Open ports found:\n" + "\n".join(open_ports)
		else:
			result = "No open ports found"
		
		return True, result
		
	except Exception as e:
		return False, f"Port scan failed: {str(e)}"

async def nikto_scan(target: str) -> Tuple[bool, str]:
	"""Simple web vulnerability scanning using Python (alternative to nikto)"""
	try:
		import requests
		
		# Add http:// if no protocol specified
		if not target.startswith(('http://', 'https://')):
			target = 'http://' + target
		
		vulnerabilities = []
		
		# Check for common web vulnerabilities
		try:
			# Check for directory listing
			response = requests.get(f"{target}/images/", timeout=5)
			if response.status_code == 200 and ('Index of' in response.text or 'Parent Directory' in response.text):
				vulnerabilities.append("Directory listing enabled")
		except:
			pass
		
		try:
			# Check for backup files
			backup_extensions = ['.bak', '.backup', '.old', '.tmp', '.temp', '.swp', '.swo']
			for ext in backup_extensions:
				response = requests.get(f"{target}/index{ext}", timeout=5)
				if response.status_code == 200:
					vulnerabilities.append(f"Backup file accessible: index{ext}")
					break
		except:
			pass
		
		try:
			# Check for common admin panels
			admin_paths = ['/admin', '/administrator', '/admin.php', '/admin.html', '/wp-admin', '/phpmyadmin']
			for path in admin_paths:
				response = requests.get(f"{target}{path}", timeout=5)
				if response.status_code in [200, 301, 302, 403]:
					vulnerabilities.append(f"Admin panel accessible: {path}")
		except:
			pass
		
		try:
			# Check for server information disclosure
			response = requests.get(target, timeout=5)
			server = response.headers.get('Server', '')
			if server and ('apache' in server.lower() or 'nginx' in server.lower()):
				vulnerabilities.append(f"Server information disclosed: {server}")
		except:
			pass
		
		try:
			# Check for security headers
			response = requests.get(target, timeout=5)
			security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection', 'Strict-Transport-Security']
			missing_headers = []
			for header in security_headers:
				if header not in response.headers:
					missing_headers.append(header)
			if missing_headers:
				vulnerabilities.append(f"Missing security headers: {', '.join(missing_headers)}")
		except:
			pass
		
		if vulnerabilities:
			result = "Web vulnerabilities found:\n" + "\n".join(vulnerabilities)
		else:
			result = "No obvious web vulnerabilities detected"
		
		return True, result
		
	except Exception as e:
		return False, f"Web vulnerability scan failed: {str(e)}"

async def theharvester_run(domain: str) -> Tuple[bool, str]:
	"""Simple email and subdomain harvesting using Python (alternative to theHarvester)"""
	try:
		import requests
		import re
		
		# Try to find emails and subdomains from common sources
		results = []
		
		# Check for emails in common paths
		email_paths = ['/contact', '/about', '/team', '/staff', '/people']
		for path in email_paths:
			try:
				url = f"http://{domain}{path}"
				response = requests.get(url, timeout=5)
				if response.status_code == 200:
					# Look for email patterns
					emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response.text)
					for email in emails:
						if domain in email:
							results.append(f"Email found: {email}")
			except:
				continue
		
		# Check for subdomains in common paths
		subdomain_paths = ['/sitemap.xml', '/robots.txt', '/.well-known/security.txt']
		for path in subdomain_paths:
			try:
				url = f"http://{domain}{path}"
				response = requests.get(url, timeout=5)
				if response.status_code == 200:
					# Look for subdomain patterns
					subdomains = re.findall(rf'[a-zA-Z0-9.-]+\.{domain.replace(".", r"\.")}', response.text)
					for subdomain in subdomains:
						if subdomain != domain:
							results.append(f"Subdomain found: {subdomain}")
			except:
				continue
		
		if results:
			result = "Harvested information:\n" + "\n".join(set(results))
		else:
			result = "No emails or subdomains found"
		
		return True, result
		
	except Exception as e:
		return False, f"Harvesting failed: {str(e)}"

async def sniper_scan(target: str) -> Tuple[bool, str]:
	"""Comprehensive reconnaissance scan using Python (alternative to sniper)"""
	try:
		import requests
		import socket
		import dns.resolver
		
		results = []
		results.append(f"=== SNIPER SCAN RESULTS FOR {target} ===")
		
		# Port scan
		common_ports = [21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 161, 389, 443, 445, 465, 587, 993, 995, 1433, 1521, 1723, 2375, 2376, 27017, 3306, 3389, 5432, 5900, 6379, 8000, 8008, 8080, 8443]
		open_ports = []
		for port in common_ports:
			try:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(1)
				result = sock.connect_ex((target, port))
				if result == 0:
					try:
						service = socket.getservbyport(port)
					except:
						service = "unknown"
					open_ports.append(f"{port} ({service})")
				sock.close()
			except:
				continue
		
		if open_ports:
			results.append(f"Open ports: {', '.join(open_ports)}")
		else:
			results.append("No open ports found")
		
		# Web scan if HTTP ports are open
		if any('80' in port or '443' in port or '8080' in port for port in open_ports):
			try:
				protocol = 'https' if any('443' in port for port in open_ports) else 'http'
				url = f"{protocol}://{target}"
				response = requests.get(url, timeout=10, allow_redirects=True)
				
				results.append(f"Web server: {response.status_code}")
				results.append(f"Server: {response.headers.get('Server', 'N/A')}")
				results.append(f"Content-Type: {response.headers.get('Content-Type', 'N/A')}")
				
				# Check for common vulnerabilities
				if 'text/html' in response.headers.get('Content-Type', ''):
					if 'admin' in response.text.lower():
						results.append("Admin panel references found")
					if 'password' in response.text.lower():
						results.append("Password references found")
					if 'error' in response.text.lower():
						results.append("Error messages found")
						
			except Exception as e:
				results.append(f"Web scan error: {str(e)}")
		
		# DNS scan if domain
		if '.' in target:
			try:
				answers = dns.resolver.resolve(target, 'A')
				results.append(f"DNS A records: {', '.join([str(answer) for answer in answers])}")
			except:
				results.append("DNS resolution failed")
		
		result = "\n".join(results)
		return True, result
		
	except Exception as e:
		return False, f"Sniper scan failed: {str(e)}"

# ProjectDiscovery ecosystem
async def subfinder(domain: str) -> Tuple[bool, str]:
	"""Simple subdomain enumeration using Python"""
	try:
		import requests
		import dns.resolver
		
		# Common subdomains to check
		common_subdomains = [
			'www', 'mail', 'ftp', 'admin', 'blog', 'api', 'dev', 'test', 'stage',
			'beta', 'support', 'help', 'docs', 'cdn', 'static', 'img', 'images',
			'files', 'download', 'upload', 'secure', 'login', 'portal', 'app',
			'web', 'site', 'server', 'ns1', 'ns2', 'mx', 'smtp', 'pop', 'imap'
		]
		
		found_subdomains = []
		for subdomain in common_subdomains:
			try:
				full_domain = f"{subdomain}.{domain}"
				answers = dns.resolver.resolve(full_domain, 'A')
				if answers:
					found_subdomains.append(full_domain)
			except:
				continue
		
		if found_subdomains:
			result = f"Found subdomains:\n" + "\n".join(found_subdomains)
			return True, result
		else:
			return True, "No common subdomains found"
			
	except Exception as e:
		return False, f"Subdomain scan failed: {str(e)}"

async def amass_enum(domain: str) -> Tuple[bool, str]:
	"""Simple subdomain enumeration using Python (alternative to amass)"""
	try:
		import requests
		import dns.resolver
		
		# Extended list of common subdomains
		common_subdomains = [
			'www', 'mail', 'ftp', 'admin', 'blog', 'api', 'dev', 'test', 'stage',
			'beta', 'support', 'help', 'docs', 'cdn', 'static', 'img', 'images',
			'files', 'download', 'upload', 'secure', 'login', 'portal', 'app',
			'web', 'site', 'server', 'ns1', 'ns2', 'mx', 'smtp', 'pop', 'imap',
			'mobile', 'm', 'shop', 'store', 'ecommerce', 'news', 'forum', 'chat',
			'status', 'monitor', 'dashboard', 'analytics', 'stats', 'report',
			'old', 'legacy', 'archive', 'backup', 'db', 'database', 'sql',
			'redis', 'cache', 'search', 'find', 'lookup', 'whois', 'dns'
		]
		
		found_subdomains = []
		for subdomain in common_subdomains:
			try:
				full_domain = f"{subdomain}.{domain}"
				answers = dns.resolver.resolve(full_domain, 'A')
				if answers:
					found_subdomains.append(full_domain)
			except:
				continue
		
		if found_subdomains:
			result = f"Found subdomains:\n" + "\n".join(found_subdomains)
		else:
			result = "No subdomains found"
		
		return True, result
		
	except Exception as e:
		return False, f"Subdomain enumeration failed: {str(e)}"

async def nuclei_scan(target: str) -> Tuple[bool, str]:
	"""Simple vulnerability scanning using Python (alternative to nuclei)"""
	try:
		import requests
		
		# Add http:// if no protocol specified
		if not target.startswith(('http://', 'https://')):
			target = 'http://' + target
		
		vulnerabilities = []
		
		# Check for common vulnerabilities
		try:
			# Check for directory traversal
			test_paths = ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts']
			for path in test_paths:
				response = requests.get(f"{target}/{path}", timeout=5, allow_redirects=False)
				if response.status_code == 200 and ('root:' in response.text or 'localhost' in response.text):
					vulnerabilities.append("Potential directory traversal vulnerability")
					break
		except:
			pass
		
		try:
			# Check for open redirect
			response = requests.get(f"{target}/redirect?url=https://evil.com", timeout=5, allow_redirects=False)
			if response.status_code in [301, 302] and 'evil.com' in response.headers.get('Location', ''):
				vulnerabilities.append("Potential open redirect vulnerability")
		except:
			pass
		
		try:
			# Check for information disclosure
			response = requests.get(f"{target}/robots.txt", timeout=5)
			if response.status_code == 200 and response.text:
				vulnerabilities.append("Robots.txt accessible")
		except:
			pass
		
		try:
			# Check for server information
			response = requests.get(target, timeout=5)
			server = response.headers.get('Server', '')
			if server and ('debug' in server.lower() or 'test' in server.lower()):
				vulnerabilities.append("Server information disclosure")
		except:
			pass
		
		if vulnerabilities:
			result = "Vulnerabilities found:\n" + "\n".join(vulnerabilities)
		else:
			result = "No obvious vulnerabilities detected"
		
		return True, result
		
	except Exception as e:
		return False, f"Vulnerability scan failed: {str(e)}"

async def naabu_scan(target: str) -> Tuple[bool, str]:
	"""Simple port scanning using Python"""
	try:
		import socket
		
		# Common ports to scan
		common_ports = [21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 161, 389, 443, 445, 465, 587, 993, 995, 1433, 1521, 1723, 2375, 2376, 27017, 3306, 3389, 5432, 5900, 6379, 8000, 8008, 8080, 8443]
		
		open_ports = []
		for port in common_ports:
			try:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(1)
				result = sock.connect_ex((target, port))
				if result == 0:
					# Try to get service name
					try:
						service = socket.getservbyport(port)
					except:
						service = "unknown"
					open_ports.append(f"{port} ({service})")
				sock.close()
			except:
				continue
		
		if open_ports:
			result = f"Open ports found:\n" + "\n".join(open_ports)
		else:
			result = "No open ports found"
		
		return True, result
		
	except Exception as e:
		return False, f"Port scan failed: {str(e)}"

async def dnsx_check(domain: str) -> Tuple[bool, str]:
	"""Simple DNS enumeration using Python"""
	try:
		import dns.resolver
		
		# Common record types to check
		record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
		
		dns_records = {}
		for record_type in record_types:
			try:
				answers = dns.resolver.resolve(domain, record_type)
				if answers:
					dns_records[record_type] = [str(answer) for answer in answers]
			except:
				continue
		
		if dns_records:
			result = "DNS Records found:\n"
			for record_type, records in dns_records.items():
				result += f"{record_type}: {', '.join(records)}\n"
		else:
			result = "No DNS records found"
		
		return True, result
		
	except Exception as e:
		return False, f"DNS check failed: {str(e)}"

async def httpx_probe(target: str) -> Tuple[bool, str]:
	"""Simple HTTP probing using Python"""
	try:
		import requests
		
		# Add http:// if no protocol specified
		if not target.startswith(('http://', 'https://')):
			target = 'http://' + target
		
		response = requests.get(target, timeout=10, allow_redirects=True)
		
		# Get response details
		status_code = response.status_code
		content_type = response.headers.get('Content-Type', '')
		content_length = len(response.content)
		server = response.headers.get('Server', '')
		
		# Try to get title from HTML
		title = ''
		if 'text/html' in content_type:
			try:
				from bs4 import BeautifulSoup
				soup = BeautifulSoup(response.text, 'html.parser')
				title_tag = soup.find('title')
				if title_tag:
					title = title_tag.get_text().strip()
			except:
				pass
		
		result = f"""HTTP Probe Results:
Status: {status_code}
Content-Type: {content_type}
Content-Length: {content_length}
Server: {server}
Title: {title if title else 'N/A'}"""
		
		return True, result
		
	except Exception as e:
		return False, f"HTTP probe failed: {str(e)}"

# Other reconnaissance tools
async def whatweb_scan(target: str) -> Tuple[bool, str]:
	"""Simple web technology detection using Python"""
	try:
		import requests
		from bs4 import BeautifulSoup
		
		# Add http:// if no protocol specified
		if not target.startswith(('http://', 'https://')):
			target = 'http://' + target
		
		response = requests.get(target, timeout=10, allow_redirects=True)
		html = response.text
		soup = BeautifulSoup(html, 'html.parser')
		
		# Detect technologies
		technologies = []
		
		# Check for common frameworks
		if 'bootstrap' in html.lower():
			technologies.append('Bootstrap')
		if 'jquery' in html.lower():
			technologies.append('jQuery')
		if 'react' in html.lower():
			technologies.append('React')
		if 'angular' in html.lower():
			technologies.append('Angular')
		if 'vue' in html.lower():
			technologies.append('Vue.js')
		
		# Check for common servers
		server = response.headers.get('Server', '')
		if server:
			technologies.append(f'Server: {server}')
		
		# Check for common CMS
		if 'wordpress' in html.lower():
			technologies.append('WordPress')
		if 'joomla' in html.lower():
			technologies.append('Joomla')
		if 'drupal' in html.lower():
			technologies.append('Drupal')
		
		# Check for common analytics
		if 'google-analytics' in html.lower() or 'gtag' in html.lower():
			technologies.append('Google Analytics')
		if 'facebook' in html.lower() and 'pixel' in html.lower():
			technologies.append('Facebook Pixel')
		
		result = f"Target: {target}\nStatus: {response.status_code}\nTechnologies: {', '.join(technologies) if technologies else 'None detected'}"
		return True, result
		
	except Exception as e:
		return False, f"Web scan failed: {str(e)}"

async def wafw00f_scan(target: str) -> Tuple[bool, str]:
	"""Simple WAF detection using Python"""
	try:
		import requests
		
		# Add http:// if no protocol specified
		if not target.startswith(('http://', 'https://')):
			target = 'http://' + target
		
		response = requests.get(target, timeout=10, allow_redirects=True)
		headers = response.headers
		
		# Check for common WAF signatures
		waf_signatures = {
			'Cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
			'Cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
			'Akamai': ['x-akamai-transformed', 'akamai-origin-hop'],
			'Fastly': ['x-fastly', 'fastly-ssl'],
			'Imperva': ['incap_ses', 'visid_incap'],
			'F5 BIG-IP': ['x-wa-info', 'x-asg'],
			'Barracuda': ['barra_counter_session', 'barra_counter'],
			'Citrix NetScaler': ['ns_af', 'citrix_ns_id'],
			'ModSecurity': ['mod_security', 'modsecurity'],
			'Sucuri': ['x-sucuri', 'sucuri'],
			'Wordfence': ['wordfence-verified', 'wf-verified'],
			'Joomla': ['x-content-type-options'],
			'Drupal': ['x-generator']
		}
		
		detected_wafs = []
		for waf_name, signatures in waf_signatures.items():
			for header_name in headers:
				if any(sig.lower() in header_name.lower() for sig in signatures):
					detected_wafs.append(waf_name)
					break
		
		# Check for server headers
		server = headers.get('Server', '')
		if server:
			if 'cloudflare' in server.lower():
				detected_wafs.append('Cloudflare')
			elif 'akamai' in server.lower():
				detected_wafs.append('Akamai')
			elif 'fastly' in server.lower():
				detected_wafs.append('Fastly')
		
		if detected_wafs:
			result = f"WAF detected: {', '.join(set(detected_wafs))}"
		else:
			result = "No WAF detected"
		
		return True, result
		
	except Exception as e:
		return False, f"WAF detection failed: {str(e)}"

async def sublist3r_run(domain: str) -> Tuple[bool, str]:
	"""Simple subdomain enumeration using Python (alternative to sublist3r)"""
	try:
		import requests
		import dns.resolver
		
		# Extended list of common subdomains
		common_subdomains = [
			'www', 'mail', 'ftp', 'admin', 'blog', 'api', 'dev', 'test', 'stage',
			'beta', 'support', 'help', 'docs', 'cdn', 'static', 'img', 'images',
			'files', 'download', 'upload', 'secure', 'login', 'portal', 'app',
			'web', 'site', 'server', 'ns1', 'ns2', 'mx', 'smtp', 'pop', 'imap',
			'mobile', 'm', 'shop', 'store', 'ecommerce', 'news', 'forum', 'chat',
			'status', 'monitor', 'dashboard', 'analytics', 'stats', 'report',
			'old', 'legacy', 'archive', 'backup', 'db', 'database', 'sql',
			'redis', 'cache', 'search', 'find', 'lookup', 'whois', 'dns',
			'gateway', 'router', 'firewall', 'proxy', 'loadbalancer', 'lb',
			'vpn', 'remote', 'internal', 'external', 'public', 'private'
		]
		
		found_subdomains = []
		for subdomain in common_subdomains:
			try:
				full_domain = f"{subdomain}.{domain}"
				answers = dns.resolver.resolve(full_domain, 'A')
				if answers:
					found_subdomains.append(full_domain)
			except:
				continue
		
		if found_subdomains:
			result = f"Found subdomains:\n" + "\n".join(found_subdomains)
		else:
			result = "No subdomains found"
		
		return True, result
		
	except Exception as e:
		return False, f"Subdomain enumeration failed: {str(e)}"

async def gobuster_dns(domain: str) -> Tuple[bool, str]:
	"""Simple DNS brute force using Python (alternative to gobuster)"""
	try:
		import dns.resolver
		
		# Common DNS wordlist
		dns_words = [
			'www', 'mail', 'ftp', 'admin', 'blog', 'api', 'dev', 'test', 'stage',
			'beta', 'support', 'help', 'docs', 'cdn', 'static', 'img', 'images',
			'files', 'download', 'upload', 'secure', 'login', 'portal', 'app',
			'web', 'site', 'server', 'ns1', 'ns2', 'mx', 'smtp', 'pop', 'imap',
			'mobile', 'm', 'shop', 'store', 'ecommerce', 'news', 'forum', 'chat',
			'status', 'monitor', 'dashboard', 'analytics', 'stats', 'report',
			'old', 'legacy', 'archive', 'backup', 'db', 'database', 'sql',
			'redis', 'cache', 'search', 'find', 'lookup', 'whois', 'dns'
		]
		
		found_subdomains = []
		for word in dns_words:
			try:
				full_domain = f"{word}.{domain}"
				answers = dns.resolver.resolve(full_domain, 'A')
				if answers:
					found_subdomains.append(full_domain)
			except:
				continue
		
		if found_subdomains:
			result = f"DNS brute force results:\n" + "\n".join(found_subdomains)
		else:
			result = "No subdomains found via DNS brute force"
		
		return True, result
		
	except Exception as e:
		return False, f"DNS brute force failed: {str(e)}"

async def ffuf_vhost(domain: str) -> Tuple[bool, str]:
	"""Simple virtual host discovery using Python (alternative to ffuf)"""
	try:
		import requests
		
		# Common virtual host names
		vhost_words = [
			'dev', 'staging', 'test', 'beta', 'alpha', 'demo', 'admin', 'api',
			'mobile', 'm', 'app', 'web', 'www', 'mail', 'ftp', 'blog', 'shop',
			'store', 'support', 'help', 'docs', 'cdn', 'static', 'img', 'images'
		]
		
		found_vhosts = []
		for word in vhost_words:
			try:
				headers = {'Host': f'{word}.{domain}'}
				response = requests.get(f'http://{domain}', headers=headers, timeout=5, allow_redirects=False)
				if response.status_code in [200, 301, 302, 403]:
					found_vhosts.append(f"{word}.{domain} ({response.status_code})")
			except:
				continue
		
		if found_vhosts:
			result = f"Virtual hosts found:\n" + "\n".join(found_vhosts)
		else:
			result = "No virtual hosts found"
		
		return True, result
		
	except Exception as e:
		return False, f"Virtual host discovery failed: {str(e)}"

async def feroxbuster_dirs(target: str) -> Tuple[bool, str]:
	"""Simple directory scanning using Python requests"""
	try:
		import requests
		
		# Add http:// if no protocol specified
		if not target.startswith(('http://', 'https://')):
			target = 'http://' + target
		
		# Common directories to check
		common_dirs = [
			'/', '/admin', '/login', '/wp-admin', '/phpmyadmin', '/config', '/backup',
			'/api', '/docs', '/test', '/dev', '/stage', '/beta', '/old', '/archive',
			'/files', '/images', '/css', '/js', '/uploads', '/downloads', '/temp',
			'/cache', '/logs', '/includes', '/lib', '/src', '/bin', '/etc', '/var'
		]
		
		found_dirs = []
		for directory in common_dirs:
			try:
				url = target.rstrip('/') + directory
				response = requests.get(url, timeout=5, allow_redirects=False)
				if response.status_code in [200, 301, 302, 403]:
					found_dirs.append(f"{directory} ({response.status_code})")
			except:
				continue
		
		if found_dirs:
			result = f"Found directories:\n" + "\n".join(found_dirs)
			return True, result
		else:
			return True, "No common directories found"
			
	except Exception as e:
		return False, f"Directory scan failed: {str(e)}"

async def masscan_ports(target: str) -> Tuple[bool, str]:
	"""Simple port scanning using Python (alternative to masscan)"""
	try:
		import socket
		import concurrent.futures
		
		# Scan first 1024 ports
		ports_to_scan = list(range(1, 1025))
		
		def scan_port(port):
			try:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(0.5)
				result = sock.connect_ex((target, port))
				sock.close()
				if result == 0:
					try:
						service = socket.getservbyport(port)
					except:
						service = "unknown"
					return f"{port} ({service})"
				return None
			except:
				return None
		
		# Use ThreadPoolExecutor for faster scanning
		open_ports = []
		with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
			future_to_port = {executor.submit(scan_port, port): port for port in ports_to_scan}
			for future in concurrent.futures.as_completed(future_to_port):
				result = future.result()
				if result:
					open_ports.append(result)
		
		if open_ports:
			result = f"Open ports found (1-1024):\n" + "\n".join(open_ports)
		else:
			result = "No open ports found in range 1-1024"
		
		return True, result
		
	except Exception as e:
		return False, f"Port scan failed: {str(e)}"

async def aquatone_screenshot(target: str) -> Tuple[bool, str]:
	"""Simple web page analysis using Python (alternative to aquatone)"""
	try:
		import requests
		from bs4 import BeautifulSoup
		
		# Add http:// if no protocol specified
		if not target.startswith(('http://', 'https://')):
			target = 'http://' + target
		
		response = requests.get(target, timeout=10, allow_redirects=True)
		
		# Analyze the page
		analysis = []
		analysis.append(f"URL: {target}")
		analysis.append(f"Status: {response.status_code}")
		analysis.append(f"Content-Type: {response.headers.get('Content-Type', 'N/A')}")
		analysis.append(f"Content-Length: {len(response.content)}")
		analysis.append(f"Server: {response.headers.get('Server', 'N/A')}")
		
		# Parse HTML content
		if 'text/html' in response.headers.get('Content-Type', ''):
			try:
				soup = BeautifulSoup(response.text, 'html.parser')
				
				# Get title
				title = soup.find('title')
				if title:
					analysis.append(f"Title: {title.get_text().strip()}")
				
				# Count links
				links = soup.find_all('a')
				analysis.append(f"Links found: {len(links)}")
				
				# Count images
				images = soup.find_all('img')
				analysis.append(f"Images found: {len(images)}")
				
				# Count forms
				forms = soup.find_all('form')
				analysis.append(f"Forms found: {len(forms)}")
				
				# Look for interesting elements
				if soup.find_all('input', {'type': 'password'}):
					analysis.append("Login forms detected")
				if soup.find_all('script'):
					analysis.append("JavaScript detected")
				if soup.find_all('iframe'):
					analysis.append("iFrames detected")
					
			except Exception as e:
				analysis.append(f"HTML parsing error: {str(e)}")
		
		result = "\n".join(analysis)
		return True, result
		
	except Exception as e:
		return False, f"Page analysis failed: {str(e)}"


