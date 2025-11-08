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

# ============================================================================
# ADVANCED SCANNING MODULES
# ============================================================================

async def ssl_certificate_analysis(target: str) -> Tuple[bool, str]:
	"""Analyze SSL/TLS certificates for security issues"""
	try:
		import ssl
		import socket
		from datetime import datetime
		
		# Add https:// if no protocol specified
		if not target.startswith(('http://', 'https://')):
			target = 'https://' + target
		
		# Extract hostname from URL
		hostname = target.replace('https://', '').replace('http://', '').split('/')[0]
		
		context = ssl.create_default_context()
		with socket.create_connection((hostname, 443), timeout=10) as sock:
			with context.wrap_socket(sock, server_hostname=hostname) as ssock:
				cert = ssock.getpeercert()
				
				# Certificate details
				subject = dict(x[0] for x in cert['subject'])
				issuer = dict(x[0] for x in cert['issuer'])
				
				# Dates
				not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
				not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
				days_remaining = (not_after - datetime.now()).days
				
				# Security analysis
				security_issues = []
				if days_remaining < 30:
					security_issues.append(f"Certificate expires in {days_remaining} days")
				if days_remaining < 0:
					security_issues.append("Certificate has expired!")
				
				# Check for weak algorithms
				if 'sha1' in str(cert).lower():
					security_issues.append("Certificate uses weak SHA1 algorithm")
				
				result = f"""SSL Certificate Analysis for {hostname}:
Subject: {subject.get('commonName', 'N/A')}
Issuer: {issuer.get('commonName', 'N/A')}
Valid From: {cert['notBefore']}
Valid Until: {cert['notAfter']}
Days Remaining: {days_remaining}
Security Issues: {', '.join(security_issues) if security_issues else 'None detected'}"""
				
				return True, result
				
	except Exception as e:
		return False, f"SSL analysis failed: {str(e)}"

async def email_header_analysis(domain: str) -> Tuple[bool, str]:
	"""Analyze email headers and SPF/DKIM records"""
	try:
		import dns.resolver
		
		results = []
		
		# Check SPF record
		try:
			spf_records = dns.resolver.resolve(domain, 'TXT')
			for record in spf_records:
				if 'v=spf1' in str(record):
					results.append(f"SPF Record: {record}")
					break
		except:
			results.append("No SPF record found")
		
		# Check DKIM record
		try:
			dkim_records = dns.resolver.resolve(f'default._domainkey.{domain}', 'TXT')
			for record in dkim_records:
				if 'v=DKIM1' in str(record):
					results.append(f"DKIM Record: {record}")
					break
		except:
			results.append("No DKIM record found")
		
		# Check DMARC record
		try:
			dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
			for record in dmarc_records:
				if 'v=DMARC1' in str(record):
					results.append(f"DMARC Record: {record}")
					break
		except:
			results.append("No DMARC record found")
		
		# Check MX records
		try:
			mx_records = dns.resolver.resolve(domain, 'MX')
			mx_list = [f"{record.exchange} (Priority: {record.preference})" for record in mx_records]
			results.append(f"MX Records: {', '.join(mx_list)}")
		except:
			results.append("No MX records found")
		
		result = "Email Security Analysis:\n" + "\n".join(results)
		return True, result
		
	except Exception as e:
		return False, f"Email header analysis failed: {str(e)}"

async def social_media_intel(domain: str) -> Tuple[bool, str]:
	"""Gather social media intelligence"""
	try:
		import requests
		
		# Common social media platforms
		social_platforms = {
			'Facebook': f'https://www.facebook.com/{domain}',
			'Twitter': f'https://twitter.com/{domain}',
			'LinkedIn': f'https://www.linkedin.com/company/{domain}',
			'Instagram': f'https://www.instagram.com/{domain}',
			'YouTube': f'https://www.youtube.com/@{domain}',
			'GitHub': f'https://github.com/{domain}',
			'Reddit': f'https://www.reddit.com/r/{domain}'
		}
		
		found_profiles = []
		for platform, url in social_platforms.items():
			try:
				response = requests.get(url, timeout=5, allow_redirects=False)
				if response.status_code in [200, 301, 302]:
					found_profiles.append(f"{platform}: {url}")
			except:
				continue
		
		if found_profiles:
			result = "Social Media Profiles Found:\n" + "\n".join(found_profiles)
		else:
			result = "No obvious social media profiles found"
		
		return True, result
		
	except Exception as e:
		return False, f"Social media intelligence failed: {str(e)}"

async def cloud_infrastructure_detect(target: str) -> Tuple[bool, str]:
	"""Detect cloud infrastructure and services"""
	try:
		import requests
		
		# Add http:// if no protocol specified
		if not target.startswith(('http://', 'https://')):
			target = 'http://' + target
		
		cloud_indicators = {
			'AWS': ['x-amz-cf-id', 'x-amz-id-2', 'x-amz-request-id', 'x-amz-version-id'],
			'Azure': ['x-ms-version', 'x-ms-request-id', 'x-ms-blob-type'],
			'Google Cloud': ['x-goog-generation', 'x-goog-metageneration', 'x-goog-storage-class'],
			'Cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
			'Fastly': ['x-fastly', 'fastly-ssl'],
			'Heroku': ['x-request-id', 'x-runtime'],
			'DigitalOcean': ['x-datacenter', 'x-loadbalancer']
		}
		
		detected_clouds = []
		
		try:
			response = requests.get(target, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
			headers = response.headers
			
			for cloud, indicators in cloud_indicators.items():
				for header in headers:
					if any(indicator.lower() in header.lower() for indicator in indicators):
						detected_clouds.append(cloud)
						break
			
			# Check for cloud-specific subdomains
			cloud_subdomains = ['aws', 'azure', 'gcp', 'cloud', 'cdn', 'static', 'media']
			for subdomain in cloud_subdomains:
				try:
					test_url = f"http://{subdomain}.{target.replace('http://', '').replace('https://', '')}"
					response = requests.get(test_url, timeout=5, allow_redirects=False)
					if response.status_code in [200, 301, 302, 403]:
						detected_clouds.append(f"Cloud subdomain: {subdomain}")
				except:
					continue
					
		except:
			pass
		
		if detected_clouds:
			result = f"Cloud Infrastructure Detected:\n" + "\n".join(set(detected_clouds))
		else:
			result = "No obvious cloud infrastructure detected"
		
		return True, result
		
	except Exception as e:
		return False, f"Cloud infrastructure detection failed: {str(e)}"

async def api_endpoint_discovery(target: str) -> Tuple[bool, str]:
	"""Discover API endpoints and documentation"""
	try:
		import requests
		
		# Add http:// if no protocol specified
		if not target.startswith(('http://', 'https://')):
			target = 'http://' + target
		
		api_endpoints = []
		
		# Common API paths
		api_paths = [
			'/api', '/api/v1', '/api/v2', '/rest', '/graphql', '/swagger', '/docs',
			'/openapi.json', '/swagger.json', '/api-docs', '/developer', '/developers',
			'/sdk', '/client', '/clients', '/oauth', '/auth', '/login', '/register',
			'/webhook', '/callback', '/status', '/health', '/ping', '/version'
		]
		
		for path in api_paths:
			try:
				url = target.rstrip('/') + path
				response = requests.get(url, timeout=5, allow_redirects=False)
				if response.status_code in [200, 301, 302, 403, 401]:
					api_endpoints.append(f"{path} ({response.status_code})")
			except:
				continue
		
		# Check for API documentation
		doc_paths = ['/swagger-ui', '/redoc', '/api-docs', '/documentation', '/help']
		for path in doc_paths:
			try:
				url = target.rstrip('/') + path
				response = requests.get(url, timeout=5, allow_redirects=False)
				if response.status_code in [200, 301, 302]:
					api_endpoints.append(f"Documentation: {path} ({response.status_code})")
			except:
				continue
		
		if api_endpoints:
			result = f"API Endpoints Discovered:\n" + "\n".join(api_endpoints)
		else:
			result = "No obvious API endpoints found"
		
		return True, result
		
	except Exception as e:
		return False, f"API endpoint discovery failed: {str(e)}"

async def javascript_analysis(target: str) -> Tuple[bool, str]:
	"""Analyze JavaScript files for sensitive information"""
	try:
		import requests
		import re
		
		# Add http:// if no protocol specified
		if not target.startswith(('http://', 'https://')):
			target = 'http://' + target
		
		js_analysis = []
		
		try:
			response = requests.get(target, timeout=10)
			html = response.text
			
			# Find JavaScript files
			js_files = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', html)
			js_files.extend(re.findall(r'href=["\']([^"\']*\.js[^"\']*)["\']', html))
			
			js_analysis.append(f"JavaScript files found: {len(js_files)}")
			
			# Check for inline JavaScript
			inline_js = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
			if inline_js:
				js_analysis.append(f"Inline JavaScript blocks: {len(inline_js)}")
				
				# Look for sensitive patterns in inline JS
				sensitive_patterns = [
					r'api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']',
					r'password["\']?\s*[:=]\s*["\'][^"\']+["\']',
					r'token["\']?\s*[:=]\s*["\'][^"\']+["\']',
					r'secret["\']?\s*[:=]\s*["\'][^"\']+["\']',
					r'aws[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']'
				]
				
				for pattern in sensitive_patterns:
					matches = re.findall(pattern, str(inline_js), re.IGNORECASE)
					if matches:
						js_analysis.append(f"Potential sensitive data found: {len(matches)} instances")
			
			# Check for external JavaScript libraries
			external_libs = re.findall(r'https?://[^"\']*\.js', html)
			if external_libs:
				js_analysis.append(f"External JavaScript libraries: {len(external_libs)}")
				
		except Exception as e:
			js_analysis.append(f"Error analyzing JavaScript: {str(e)}")
		
		result = "JavaScript Analysis:\n" + "\n".join(js_analysis)
		return True, result
		
	except Exception as e:
		return False, f"JavaScript analysis failed: {str(e)}"

async def mobile_app_analysis(domain: str) -> Tuple[bool, str]:
	"""Analyze mobile app presence and configurations"""
	try:
		import requests
		
		mobile_analysis = []
		
		# Check for mobile app deep links
		mobile_paths = [
			'/.well-known/apple-app-site-association',
			'/.well-known/assetlinks.json',
			'/mobile', '/app', '/android', '/ios', '/mobile-app'
		]
		
		for path in mobile_paths:
			try:
				url = f"http://{domain}{path}"
				response = requests.get(url, timeout=5, allow_redirects=False)
				if response.status_code in [200, 301, 302]:
					mobile_analysis.append(f"Mobile app path: {path} ({response.status_code})")
			except:
				continue
		
		# Check for mobile-specific meta tags
		try:
			response = requests.get(f"http://{domain}", timeout=10)
			html = response.text.lower()
			
			mobile_indicators = [
				'viewport', 'mobile-optimized', 'mobile-friendly', 'responsive',
				'apple-mobile-web-app', 'mobile-web-app-capable', 'format-detection'
			]
			
			for indicator in mobile_indicators:
				if indicator in html:
					mobile_analysis.append(f"Mobile indicator: {indicator}")
					
		except:
			pass
		
		if mobile_analysis:
			result = "Mobile App Analysis:\n" + "\n".join(mobile_analysis)
		else:
			result = "No obvious mobile app configurations found"
		
		return True, result
		
	except Exception as e:
		return False, f"Mobile app analysis failed: {str(e)}"

async def geolocation_intel(target: str) -> Tuple[bool, str]:
	"""Gather geolocation and infrastructure intelligence"""
	try:
		import requests
		import socket
		
		geo_info = []
		
		# Get IP address if domain
		if '.' in target:
			try:
				ip = socket.gethostbyname(target)
				geo_info.append(f"IP Address: {ip}")
			except:
				ip = target
		else:
			ip = target
		
		# Use free geolocation service
		try:
			geo_response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
			if geo_response.status_code == 200:
				geo_data = geo_response.json()
				if geo_data.get('status') == 'success':
					geo_info.extend([
						f"Country: {geo_data.get('country', 'N/A')}",
						f"Region: {geo_data.get('regionName', 'N/A')}",
						f"City: {geo_data.get('city', 'N/A')}",
						f"ISP: {geo_data.get('isp', 'N/A')}",
						f"Organization: {geo_data.get('org', 'N/A')}",
						f"Timezone: {geo_data.get('timezone', 'N/A')}"
					])
		except:
			geo_info.append("Geolocation lookup failed")
		
		# Check for CDN presence
		try:
			response = requests.get(f"http://{target}", timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
			headers = response.headers
			
			cdn_indicators = {
				'Cloudflare': ['cf-ray', 'cf-cache-status'],
				'Akamai': ['x-akamai-transformed'],
				'Fastly': ['x-fastly'],
				'MaxCDN': ['x-cdn'],
				'CDN77': ['x-cdn77']
			}
			
			for cdn, indicators in cdn_indicators.items():
				for header in headers:
					if any(indicator.lower() in header.lower() for indicator in indicators):
						geo_info.append(f"CDN: {cdn}")
						break
						
		except:
			pass
		
		result = "Geolocation Intelligence:\n" + "\n".join(geo_info)
		return True, result
		
	except Exception as e:
		return False, f"Geolocation intelligence failed: {str(e)}"

async def technology_stack_profiling(target: str) -> Tuple[bool, str]:
	"""Comprehensive technology stack profiling"""
	try:
		import requests
		from bs4 import BeautifulSoup
		
		# Add http:// if no protocol specified
		if not target.startswith(('http://', 'https://')):
			target = 'http://' + target
		
		tech_stack = []
		
		try:
			response = requests.get(target, timeout=15, headers={
				'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
			})
			html = response.text
			headers = response.headers
			
			# Server technologies
			server = headers.get('Server', '')
			if server:
				tech_stack.append(f"Server: {server}")
			
			# Programming languages and frameworks
			language_indicators = {
				'PHP': ['php', 'wordpress', 'joomla', 'drupal', 'laravel', 'symfony'],
				'Python': ['python', 'django', 'flask', 'fastapi', 'bottle'],
				'Node.js': ['node', 'express', 'next.js', 'nuxt.js', 'react', 'vue'],
				'Java': ['java', 'spring', 'struts', 'jsf', 'servlet'],
				'.NET': ['asp.net', 'dotnet', 'mvc', 'webforms', 'blazor'],
				'Ruby': ['ruby', 'rails', 'sinatra', 'jekyll'],
				'Go': ['go', 'golang', 'gin', 'echo', 'fiber']
			}
			
			for language, indicators in language_indicators.items():
				if any(indicator.lower() in html.lower() for indicator in indicators):
					tech_stack.append(f"Language/Framework: {language}")
			
			# Frontend technologies
			frontend_tech = {
				'Bootstrap': ['bootstrap', 'bootstrap.min.css'],
				'jQuery': ['jquery', 'jquery.min.js'],
				'React': ['react', 'react-dom', 'jsx'],
				'Angular': ['angular', 'ng-', 'angular.js'],
				'Vue.js': ['vue', 'vue.js', 'v-'],
				'Svelte': ['svelte', 'svelte.js'],
				'TypeScript': ['typescript', '.ts', 'tsconfig']
			}
			
			for tech, indicators in frontend_tech.items():
				if any(indicator.lower() in html.lower() for indicator in indicators):
					tech_stack.append(f"Frontend: {tech}")
			
			# Database technologies
			db_indicators = {
				'MySQL': ['mysql', 'mysqli'],
				'PostgreSQL': ['postgresql', 'postgres'],
				'MongoDB': ['mongodb', 'mongoose'],
				'Redis': ['redis'],
				'SQLite': ['sqlite'],
				'Oracle': ['oracle', 'oci']
			}
			
			for db, indicators in db_indicators.items():
				if any(indicator.lower() in html.lower() for indicator in indicators):
					tech_stack.append(f"Database: {db}")
			
			# Cloud and hosting
			cloud_indicators = {
				'AWS': ['aws', 'amazon', 's3', 'ec2', 'lambda'],
				'Azure': ['azure', 'microsoft', 'blob', 'function'],
				'Google Cloud': ['gcp', 'google', 'cloud', 'firebase'],
				'Heroku': ['heroku'],
				'DigitalOcean': ['digitalocean', 'do'],
				'Vercel': ['vercel'],
				'Netlify': ['netlify']
			}
			
			for cloud, indicators in cloud_indicators.items():
				if any(indicator.lower() in html.lower() for indicator in indicators):
					tech_stack.append(f"Cloud/Hosting: {cloud}")
			
			# Analytics and tracking
			analytics_tech = {
				'Google Analytics': ['google-analytics', 'gtag', 'ga('],
				'Google Tag Manager': ['gtm', 'googletagmanager'],
				'Facebook Pixel': ['facebook', 'fbq', 'pixel'],
				'Hotjar': ['hotjar'],
				'Mixpanel': ['mixpanel'],
				'Amplitude': ['amplitude']
			}
			
			for analytics, indicators in analytics_tech.items():
				if any(indicator.lower() in html.lower() for indicator in indicators):
					tech_stack.append(f"Analytics: {analytics}")
					
		except Exception as e:
			tech_stack.append(f"Error analyzing technology stack: {str(e)}")
		
		if tech_stack:
			result = "Technology Stack Profile:\n" + "\n".join(tech_stack)
		else:
			result = "No obvious technologies detected"
		
		return True, result
		
	except Exception as e:
		return False, f"Technology stack profiling failed: {str(e)}"

# ============================================================================
# SCANNING ORCHESTRATION FUNCTIONS
# ============================================================================

async def run_advanced_scans(target: str) -> Dict[str, Tuple[bool, str]]:
	"""Run all advanced scanning modules"""
	advanced_scans = {
		'ssl_analysis': ssl_certificate_analysis,
		'email_security': email_header_analysis,
		'social_intel': social_media_intel,
		'cloud_detect': cloud_infrastructure_detect,
		'api_discovery': api_endpoint_discovery,
		'js_analysis': javascript_analysis,
		'mobile_analysis': mobile_app_analysis,
		'geo_intel': geolocation_intel,
		'tech_profiling': technology_stack_profiling
	}
	
	results = {}
	for scan_name, scan_func in advanced_scans.items():
		try:
			results[scan_name] = await scan_func(target)
		except Exception as e:
			results[scan_name] = (False, f"Scan failed: {str(e)}")
	
	return results


