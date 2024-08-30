# import yaml
# import requests
# import logging
# from together import Together
# from zapv2 import ZAPv2
# import time

# # Configure logging
# logging.basicConfig(filename='test_case.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# # Initialize OWASP ZAP
# zap_base_url = 'http://localhost:8080'
# zap = ZAPv2(apikey='abc123abc', proxies={'http': zap_base_url, 'https': zap_base_url})

# # 1. Load API Endpoints
# def load_api_endpoints(file_path):
#     try:
#         with open(file_path, 'r') as file:
#             return yaml.safe_load(file)
#     except Exception as e:
#         logging.error(f"Error loading API endpoints: {e}")
#         raise

# # 2. Initialize Together Client
# together_client = Together(api_key="ec9520d163d357d5ed7414ed993c027fdcd36c7d5c64149811fcc85f201db981")

# # 3. Generate Test Cases using LLM
# def generate_test_cases(api_endpoint):
#     try:
#         response = together_client.chat.completions.create(
#             model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
#             messages=[
#                 {
#                     "role": "system",
#                     "content": "You are an API security expert. Generate test cases for the following API endpoint."
#                 },
#                 {
#                     "role": "user",
#                     "content": f"""
#                     API URL: {api_endpoint['url']}
#                     Headers:
#                     {', '.join([f'{key}: {value}' for key, value in api_endpoint['headers'].items()])}
#                     """
#                 }
#             ],
#             max_tokens=500
#         )
        
#         test_case_text = response.choices[0].message.content
#         logging.info(f"Generated Test Case for URL {api_endpoint['url']}: {test_case_text}")
#         return test_case_text
#     except Exception as e:
#         logging.error(f"Error generating test case: {e}")
#         raise

# # 4. Generate Advanced Test Cases
# # 4. Generate Advanced Test Cases
# def generate_advanced_test_cases(api_endpoint):
#     advanced_cases = [
#         {
#             "description": "Broken Object Level Authorization",
#             "method": "GET",
#             "url": f"{api_endpoint['url']}/object_level_access",
#             "headers": api_endpoint['headers'],
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Broken Authentication",
#             "method": "POST",
#             "url": f"{api_endpoint['url']}/login",
#             "headers": api_endpoint['headers'],
#             "data": {"username": "admin", "password": "wrong_password"},
#             "expected_status": 401,
#             "expected_response": "Invalid credentials"
#         },
#         {
#             "description": "Broken Object Property Level Authorization",
#             "method": "GET",
#             "url": f"{api_endpoint['url']}/object_property",
#             "headers": api_endpoint['headers'],
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Unrestricted Resource Consumption",
#             "method": "GET",
#             "url": f"{api_endpoint['url']}/resource_consumption",
#             "headers": api_endpoint['headers'],
#             "expected_status": 429,  # Too Many Requests
#             "expected_response": "Rate limit exceeded"
#         },
#         {
#             "description": "Broken Function Level Authorization",
#             "method": "POST",
#             "url": f"{api_endpoint['url']}/admin_function",
#             "headers": api_endpoint['headers'],
#             "data": {"action": "admin_action"},
#             "expected_status": 403,
#             "expected_response": "Forbidden"
#         },
#         {
#             "description": "Unrestricted Access to Sensitive Business Flows",
#             "method": "POST",
#             "url": f"{api_endpoint['url']}/sensitive_flow",
#             "headers": api_endpoint['headers'],
#             "data": {"action": "excessive_use"},
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Server Side Request Forgery (SSRF)",
#             "method": "POST",
#             "url": f"{api_endpoint['url']}/ssrf_vulnerable",
#             "headers": api_endpoint['headers'],
#             "data": {"url": "http://internal_service:8080"},
#             "expected_status": 403,
#             "expected_response": "Forbidden"
#         },
#         {
#             "description": "Security Misconfiguration",
#             "method": "GET",
#             "url": f"{api_endpoint['url']}/config",
#             "headers": api_endpoint['headers'],
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Improper Inventory Management",
#             "method": "GET",
#             "url": f"{api_endpoint['url']}/api_versions",
#             "headers": api_endpoint['headers'],
#             "expected_status": 200,
#             "expected_response": "List of versions"
#         },
#         {
#             "description": "Unsafe Consumption of APIs",
#             "method": "POST",
#             "url": f"{api_endpoint['url']}/consume_third_party",
#             "headers": api_endpoint['headers'],
#             "data": {"third_party_url": "http://malicious_service.com"},
#             "expected_status": 400,
#             "expected_response": "Bad Request"
#         }
#     ]
#     return advanced_cases


# # 5. Execute Basic Test Cases
# def execute_test_case(api_endpoint):
#     try:
#         url = api_endpoint['url']
#         headers = api_endpoint['headers']
#         response = requests.get(url, headers=headers)
#         return response.status_code, response.text
#     except Exception as e:
#         logging.error(f"Error executing test case: {e}")
#         return None, str(e)

# # 6. Execute Advanced Test Cases
# def execute_advanced_test_case(api_endpoint, test_case):
#     try:
#         url = test_case['url']
#         headers = test_case['headers']
#         data = test_case.get('data', {})
#         if test_case['method'] == 'POST':
#             response = requests.post(url, headers=headers, data=data)
#         else:
#             response = requests.get(url, headers=headers)
#         return response.status_code, response.text
#     except Exception as e:
#         logging.error(f"Error executing advanced test case: {e}")
#         return None, str(e)

# # 7. OWASP ZAP Scanning
# def run_zap_scan(api_endpoints):
#     scan_results = []
#     for endpoint in api_endpoints:
#         url = endpoint['url']
#         try:
#             print(f"Scanning URL: {url}")
            
#             # Access URL
#             zap.urlopen(url)
#             time.sleep(2)  # Wait for the URL to be processed
            
#             # Start Spider
#             print(f"Starting spider scan on {url}")
#             zap.spider.scan(url)
#             while int(zap.spider.status()) < 100:
#                 print(f'Spidering... {zap.spider.status()}%')
#                 time.sleep(2)
#             print('Spider scan completed')
            
#             # Start Active Scan
#             print(f"Starting active scan on {url}")
#             zap.ascan.scan(url)
#             while int(zap.ascan.status()) < 100:
#                 print(f'Active scanning... {zap.ascan.status()}%')
#                 time.sleep(2)
#             print('Active scan completed')
            
#             # Get Alerts
#             alerts = zap.core.alerts(baseurl=url)
#             scan_results.append({'url': url, 'alerts': alerts})
#         except Exception as e:
#             logging.error(f"Error during ZAP scan: {e}")
#             scan_results.append({'url': url, 'alerts': [], 'error': str(e)})
#     return scan_results

# # 8. Analyze Results and Generate Report
# def analyze_results(results, test_cases):
#     vulnerabilities = []
#     for idx, (status, response) in enumerate(results):
#         if status != 200:
#             vulnerabilities.append({
#                 'test_case': test_cases[idx],
#                 'status': status,
#                 'response': response
#             })
#     return vulnerabilities

# def generate_report(vulnerabilities, test_cases, zap_results):
#     with open('report.txt', 'w') as report_file:
#         if vulnerabilities:
#             for vulnerability in vulnerabilities:
#                 report_file.write(f"Test Case: {vulnerability['test_case']['description']}\n")
#                 report_file.write(f"Method: {vulnerability['test_case']['method']}\n")
#                 report_file.write(f"URL: {vulnerability['test_case']['url']}\n")
#                 report_file.write(f"Expected Status: {vulnerability['test_case']['expected_status']}\n")
#                 report_file.write(f"Expected Response: {vulnerability['test_case']['expected_response']}\n")
#                 report_file.write(f"Actual Status: {vulnerability['status']}\n")
#                 report_file.write(f"Actual Response: {vulnerability['response']}\n\n")
#                 logging.info(f"Test Case Failed: {vulnerability['test_case']['description']}")
#         else:
#             report_file.write("No vulnerabilities found.\n")
#             report_file.write("Test cases executed:\n")
#             for test_case in test_cases:
#                 report_file.write(f"{test_case}\n")
#             logging.info("All test cases passed successfully.")

#         # Add ZAP scan results to the report
#         for result in zap_results:
#             report_file.write(f"\nOWASP ZAP Scan Results for URL: {result['url']}:\n")
#             if 'error' in result:
#                 report_file.write(f"Error during scan: {result['error']}\n\n")
#             else:
#                 for alert in result['alerts']:
#                     report_file.write(f"Alert: {alert['alert']}\n")
#                     report_file.write(f"Description: {alert['description']}\n")
#                     report_file.write(f"Risk: {alert['risk']}\n")
#                     report_file.write(f"URL: {alert['url']}\n")
#                     report_file.write(f"Message: {alert['message']}\n\n")
#                     logging.info(f"OWASP ZAP Alert: {alert['description']}")

# # Main Execution Flow
# if __name__ == "__main__":
#     try:
#         # Load API Endpoints
#         api_endpoints = load_api_endpoints('api_endpoints.yaml')
#         print("Loaded API Endpoints:", api_endpoints)

#         # Generate Test Cases
#         test_cases = [generate_test_cases(endpoint) for endpoint in api_endpoints]
#         print("Generated Test Cases:", test_cases)

#         # Execute Basic Test Cases
#         results = [execute_test_case(endpoint) for endpoint in api_endpoints]
#         print("Test Case Results:", results)

#         # Generate and Execute Advanced Test Cases
#         all_vulnerabilities = []
#         for endpoint in api_endpoints:
#             advanced_test_cases = generate_advanced_test_cases(endpoint)
#             advanced_results = [execute_advanced_test_case(endpoint, case) for case in advanced_test_cases]
#             advanced_vulnerabilities = analyze_results(advanced_results, advanced_test_cases)
#             all_vulnerabilities.extend(advanced_vulnerabilities)

#         # Run OWASP ZAP Scan
#         zap_results = run_zap_scan(api_endpoints)

#         # Combine Results
#         vulnerabilities = analyze_results(results, test_cases)
#         vulnerabilities.extend(all_vulnerabilities)
#         print("Vulnerabilities found:", vulnerabilities)

#         # Generate Report
#         generate_report(vulnerabilities, test_cases, zap_results)
#         print("Report generated: report.txt")
#     except Exception as e:
#         logging.error(f"An error occurred in the main execution flow: {e}")






# import yaml
# import requests
# import logging
# from together import Together
# from zapv2 import ZAPv2
# import time

# # Configure logging
# logging.basicConfig(filename='test_case.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# # Initialize OWASP ZAP
# zap_base_url = 'http://localhost:8080'
# zap = ZAPv2(apikey='abc123abc', proxies={'http': zap_base_url, 'https': zap_base_url})

# # 1. Load API Endpoints
# def load_api_endpoints(file_path):
#     try:
#         with open(file_path, 'r') as file:
#             data = yaml.safe_load(file)
#             print(f"Loaded API Endpoints: {data}")  # Debugging print statement
#             return data
#     except Exception as e:
#         logging.error(f"Error loading API endpoints: {e}")
#         raise

# # 2. Initialize Together Client
# together_client = Together(api_key="ec9520d163d357d5ed7414ed993c027fdcd36c7d5c64149811fcc85f201db981")

# # 3. Generate Test Cases using LLM
# # def generate_test_cases(api_endpoint):
# #     try:
# #         response = together_client.chat.completions.create(
# #             model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
# #             messages=[
# #                 {
# #                     "role": "system",
# #                     "content": "You are an API security expert. Generate test cases for the following API endpoint."
# #                 },
# #                 {
# #                     "role": "user",
# #                     "content": f"""
# #                     API URL: {api_endpoint['url']}
# #                     Headers:
# #                     {', '.join([f'{key}: {value}' for key, value in api_endpoint['headers'].items()])}
# #                     """
# #                 }
# #             ],
# #             max_tokens=500
# #         )
        
# #         test_case_text = response.choices[0].message.content
# #         logging.info(f"Generated Test Case for URL {api_endpoint['url']}: {test_case_text}")
# #         return test_case_text
# #     except Exception as e:
# #         logging.error(f"Error generating test case: {e}")
# #         raise


# def generate_test_cases(api_endpoint):
#     try:
#         response = together_client.chat.completions.create(
#             model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
#             messages=[
#                 {
#                     "role": "system",
#                     "content": "You are an API security expert. Generate realistic test cases for the following API endpoint."
#                 },
#                 {
#                     "role": "user",
#                     "content": f"""
#                     API URL: {api_endpoint['url']}
#                     Headers:
#                     {', '.join([f'{key}: {value}' for key, value in api_endpoint['headers'].items()])}
#                     """
#                 }
#             ],
#             max_tokens=500
#         )
        
#         test_case_text = response.choices[0].message.content
#         logging.info(f"Generated Test Case for URL {api_endpoint['url']}: {test_case_text}")
#         return test_case_text
#     except Exception as e:
#         logging.error(f"Error generating test case: {e}")
#         raise


# # 4. Generate Advanced Test Cases
# def generate_advanced_test_cases(api_endpoint):
#     advanced_cases = [

#         {
#             "description": "SQL Injection Attempt",
#             "method": "GET",
#             "url": f"{api_endpoint['url']}?id=1' OR '1'='1",
#             "headers": api_endpoint['headers'],
#             "expected_status": 400,  # Expecting a 400 Bad Request or similar
#             "expected_response": "An error message indicating improper input"
#         },
#         {
#             "description": "XSS Attack Attempt",
#             "method": "GET",
#             "url": f"{api_endpoint['url']}?name=<script>alert('XSS')</script>",
#             "headers": api_endpoint['headers'],
#             "expected_status": 400,  # Expecting a 400 Bad Request or similar
#             "expected_response": "An error message indicating improper input"
#         },
#         {
#             "description": "Large Payload Test",
#             "method": "GET",
#             "url": f"{api_endpoint['url']}?data={'A'*10000}",
#             "headers": api_endpoint['headers'],
#             "expected_status": 413,  # Expecting a 413 Payload Too Large
#             "expected_response": "An error message indicating payload too large"
#         },
#         {
#             "description": "Rate Limiting Test",
#             "method": "GET",
#             "url": f"{api_endpoint['url']}",
#             "headers": api_endpoint['headers'],
#             "expected_status": 429,  # Expecting a 429 Too Many Requests
#             "expected_response": "An error message indicating rate limit exceeded"
#         },

#         {
#             "description": "Broken Object Level Authorization",
#             "method": "GET",
#             "url": f"{api_endpoint['url']}/object_level_access",
#             "headers": api_endpoint['headers'],
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Broken Authentication",
#             "method": "POST",
#             "url": f"{api_endpoint['url']}/login",
#             "headers": api_endpoint['headers'],
#             "data": {"username": "admin", "password": "wrong_password"},
#             "expected_status": 401,
#             "expected_response": "Invalid credentials"
#         },
#         {
#             "description": "Broken Object Property Level Authorization",
#             "method": "GET",
#             "url": f"{api_endpoint['url']}/object_property",
#             "headers": api_endpoint['headers'],
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Unrestricted Resource Consumption",
#             "method": "GET",
#             "url": f"{api_endpoint['url']}/resource_consumption",
#             "headers": api_endpoint['headers'],
#             "expected_status": 429,  # Too Many Requests
#             "expected_response": "Rate limit exceeded"
#         },
#         {
#             "description": "Broken Function Level Authorization",
#             "method": "POST",
#             "url": f"{api_endpoint['url']}/admin_function",
#             "headers": api_endpoint['headers'],
#             "data": {"action": "admin_action"},
#             "expected_status": 403,
#             "expected_response": "Forbidden"
#         },
#         {
#             "description": "Unrestricted Access to Sensitive Business Flows",
#             "method": "POST",
#             "url": f"{api_endpoint['url']}/sensitive_flow",
#             "headers": api_endpoint['headers'],
#             "data": {"action": "excessive_use"},
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Server Side Request Forgery (SSRF)",
#             "method": "POST",
#             "url": f"{api_endpoint['url']}/ssrf_vulnerable",
#             "headers": api_endpoint['headers'],
#             "data": {"url": "http://internal_service:8080"},
#             "expected_status": 403,
#             "expected_response": "Forbidden"
#         },
#         {
#             "description": "Security Misconfiguration",
#             "method": "GET",
#             "url": f"{api_endpoint['url']}/config",
#             "headers": api_endpoint['headers'],
#             "expected_status": 403,
#             "expected_response": "Access denied"
#         },
#         {
#             "description": "Improper Inventory Management",
#             "method": "GET",
#             "url": f"{api_endpoint['url']}/api_versions",
#             "headers": api_endpoint['headers'],
#             "expected_status": 200,
#             "expected_response": "List of versions"
#         },
#         {
#             "description": "Unsafe Consumption of APIs",
#             "method": "POST",
#             "url": f"{api_endpoint['url']}/consume_third_party",
#             "headers": api_endpoint['headers'],
#             "data": {"third_party_url": "http://malicious_service.com"},
#             "expected_status": 400,
#             "expected_response": "Bad Request"
#         }
        
#     ]
#     return advanced_cases

# # 5. Execute Basic Test Cases
# def execute_test_case(api_endpoint):
#     try:
#         url = api_endpoint['url']
#         headers = api_endpoint['headers']
#         response = requests.get(url, headers=headers)
#         return response.status_code, response.text
#     except Exception as e:
#         logging.error(f"Error executing test case: {e}")
#         return None, str(e)

# # 6. Execute Advanced Test Cases
# def execute_advanced_test_case(api_endpoint, test_case):
#     try:
#         url = test_case['url']
#         headers = test_case['headers']
#         data = test_case.get('data', {})
#         if test_case['method'] == 'POST':
#             response = requests.post(url, headers=headers, data=data)
#         else:
#             response = requests.get(url, headers=headers)
#         return response.status_code, response.text
#     except Exception as e:
#         logging.error(f"Error executing advanced test case: {e}")
#         return None, str(e)

# # 7. OWASP ZAP Scanning
# def run_zap_scan(api_endpoints):
#     scan_results = []
#     for endpoint in api_endpoints:
#         url = endpoint['url']
#         try:
#             print(f"Scanning URL: {url}")
            
#             # Access URL
#             zap.urlopen(url)
#             time.sleep(2)  # Wait for the URL to be processed
            
#             # Start Spider
#             print(f"Starting spider scan on {url}")
#             zap.spider.scan(url)
#             while int(zap.spider.status()) < 100:
#                 print(f'Spidering... {zap.spider.status()}%')
#                 time.sleep(2)
#             print('Spider scan completed')
            
#             # Start Active Scan
#             print(f"Starting active scan on {url}")
#             zap.ascan.scan(url)
#             while int(zap.ascan.status()) < 100:
#                 print(f'Active scanning... {zap.ascan.status()}%')
#                 time.sleep(2)
#             print('Active scan completed')
            
#             # Get Alerts
#             alerts = zap.core.alerts(baseurl=url)
#             scan_results.append({'url': url, 'alerts': alerts})
#         except Exception as e:
#             logging.error(f"Error during ZAP scan: {e}")
#             scan_results.append({'url': url, 'alerts': [], 'error': str(e)})
#     return scan_results

# # 8. Analyze Results and Generate Report
# def analyze_results(results, test_cases):
#     vulnerabilities = []
#     for idx, (status, response) in enumerate(results):
#         if status != 200:
#             vulnerabilities.append({
#                 'test_case': test_cases[idx],
#                 'status': status,
#                 'response': response
#             })
#     return vulnerabilities

# def generate_report(vulnerabilities, test_cases, zap_results):
#     with open('report.txt', 'w') as report_file:
#         if vulnerabilities:
#             for vulnerability in vulnerabilities:
#                 report_file.write(f"Test Case: {vulnerability['test_case']['description']}\n")
#                 report_file.write(f"Method: {vulnerability['test_case']['method']}\n")
#                 report_file.write(f"URL: {vulnerability['test_case']['url']}\n")
#                 report_file.write(f"Expected Status: {vulnerability['test_case']['expected_status']}\n")
#                 report_file.write(f"Expected Response: {vulnerability['test_case']['expected_response']}\n")
#                 report_file.write(f"Actual Status: {vulnerability['status']}\n")
#                 report_file.write(f"Actual Response: {vulnerability['response']}\n")
#                 report_file.write("\n")
        
#         if zap_results:
#             for result in zap_results:
#                 report_file.write(f"URL: {result['url']}\n")
#                 if 'alerts' in result:
#                     for alert in result['alerts']:
#                         report_file.write(f"Alert: {alert['alert']}\n")
#                 if 'error' in result:
#                     report_file.write(f"Error: {result['error']}\n")
#                 report_file.write("\n")

# # Main script execution
# if __name__ == '__main__':
#     api_endpoints = load_api_endpoints('api_endpoints.yaml')

#     all_test_cases = []
#     for endpoint in api_endpoints:
#         # Generate Basic Test Cases
#         basic_test_case = generate_test_cases(endpoint)
#         all_test_cases.append(basic_test_case)
        
#         # Generate and Execute Advanced Test Cases
#         advanced_test_cases = generate_advanced_test_cases(endpoint)
#         for test_case in advanced_test_cases:
#             all_test_cases.append(test_case)
    
#     # Execute All Test Cases
#     results = [execute_test_case(endpoint) for endpoint in api_endpoints]
#     advanced_results = [execute_advanced_test_case(endpoint, test_case) for endpoint in api_endpoints for test_case in generate_advanced_test_cases(endpoint)]
#     all_results = results + advanced_results

#     # Run OWASP ZAP Scan
#     zap_results = run_zap_scan(api_endpoints)

#     # Analyze and Report
#     vulnerabilities = analyze_results(all_results, all_test_cases)
#     generate_report(vulnerabilities, all_test_cases, zap_results)







# import yaml
# import requests
# import logging
# from together import Together
# from zapv2 import ZAPv2
# import time

# # Configure logging
# logging.basicConfig(filename='test_case.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# # Initialize OWASP ZAP
# zap_base_url = 'http://localhost:8080'
# zap = ZAPv2(apikey='abc123abc', proxies={'http': zap_base_url, 'https': zap_base_url})

# # Initialize Together Client
# together_client = Together(api_key="ec9520d163d357d5ed7414ed993c027fdcd36c7d5c64149811fcc85f201db981")

# # 1. Load API Endpoints
# def load_api_endpoints(file_path):
#     try:
#         with open(file_path, 'r') as file:
#             data = yaml.safe_load(file)
#             logging.info(f"Loaded API Endpoints: {data}")  # Logging instead of print
#             return data
#     except Exception as e:
#         logging.error(f"Error loading API endpoints: {e}")
#         raise

# # 2. Generate Test Cases using LLM
# def generate_test_cases(api_endpoint):
#     try:
#         response = together_client.chat.completions.create(
#             model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
#             messages=[
#                 {
#                     "role": "system",
#                     "content": "You are an API security expert. Generate realistic test cases for the following API endpoint."
#                 },
#                 {
#                     "role": "user",
#                     "content": f"""
#                     API URL: {api_endpoint['url']}
#                     Headers:
#                     {', '.join([f'{key}: {value}' for key, value in api_endpoint['headers'].items()])}
#                     """
#                 }
#             ],
#             max_tokens=500
#         )
        
#         test_case_text = response.choices[0].message.content
#         logging.info(f"Generated Test Case for URL {api_endpoint['url']}: {test_case_text}")
#         return test_case_text
#     except Exception as e:
#         logging.error(f"Error generating test case: {e}")
#         raise

# # 3. Generate Advanced Test Cases
# def generate_advanced_test_cases(api_endpoint):
#     advanced_cases = [
        # {
        #     "description": "SQL Injection Attempt",
        #     "method": "GET",
        #     "url": f"{api_endpoint['url']}?id=1' OR '1'='1",
        #     "headers": api_endpoint['headers'],
        #     "expected_status": 400,
        #     "expected_response": "An error message indicating improper input"
        # },
        # {
        #     "description": "XSS Attack Attempt",
        #     "method": "GET",
        #     "url": f"{api_endpoint['url']}?name=<script>alert('XSS')</script>",
        #     "headers": api_endpoint['headers'],
        #     "expected_status": 400,
        #     "expected_response": "An error message indicating improper input"
        # },
        # {
        #     "description": "Large Payload Test",
        #     "method": "GET",
        #     "url": f"{api_endpoint['url']}?data={'A'*10000}",
        #     "headers": api_endpoint['headers'],
        #     "expected_status": 413,
        #     "expected_response": "An error message indicating payload too large"
        # },
        # {
        #     "description": "Rate Limiting Test",
        #     "method": "GET",
        #     "url": f"{api_endpoint['url']}",
        #     "headers": api_endpoint['headers'],
        #     "expected_status": 429,
        #     "expected_response": "An error message indicating rate limit exceeded"
        # },
        # {
        #     "description": "Broken Object Level Authorization",
        #     "method": "GET",
        #     "url": f"{api_endpoint['url']}/object_level_access",
        #     "headers": api_endpoint['headers'],
        #     "expected_status": 403,
        #     "expected_response": "Access denied"
        # },
        # {
        #     "description": "Broken Authentication",
        #     "method": "POST",
        #     "url": f"{api_endpoint['url']}/login",
        #     "headers": api_endpoint['headers'],
        #     "data": {"username": "admin", "password": "wrong_password"},
        #     "expected_status": 401,
        #     "expected_response": "Invalid credentials"
        # },
        # {
        #     "description": "Broken Object Property Level Authorization",
        #     "method": "GET",
        #     "url": f"{api_endpoint['url']}/object_property",
        #     "headers": api_endpoint['headers'],
        #     "expected_status": 403,
        #     "expected_response": "Access denied"
        # },
        # {
        #     "description": "Unrestricted Resource Consumption",
        #     "method": "GET",
        #     "url": f"{api_endpoint['url']}/resource_consumption",
        #     "headers": api_endpoint['headers'],
        #     "expected_status": 429,
        #     "expected_response": "Rate limit exceeded"
        # },
        # {
        #     "description": "Broken Function Level Authorization",
        #     "method": "POST",
        #     "url": f"{api_endpoint['url']}/admin_function",
        #     "headers": api_endpoint['headers'],
        #     "data": {"action": "admin_action"},
        #     "expected_status": 403,
        #     "expected_response": "Forbidden"
        # },
        # {
        #     "description": "Unrestricted Access to Sensitive Business Flows",
        #     "method": "POST",
        #     "url": f"{api_endpoint['url']}/sensitive_flow",
        #     "headers": api_endpoint['headers'],
        #     "data": {"action": "excessive_use"},
        #     "expected_status": 403,
        #     "expected_response": "Access denied"
        # },
        # {
        #     "description": "Server Side Request Forgery (SSRF)",
        #     "method": "POST",
        #     "url": f"{api_endpoint['url']}/ssrf_vulnerable",
        #     "headers": api_endpoint['headers'],
        #     "data": {"url": "http://internal_service:8080"},
        #     "expected_status": 403,
        #     "expected_response": "Forbidden"
        # },
        # {
        #     "description": "Security Misconfiguration",
        #     "method": "GET",
        #     "url": f"{api_endpoint['url']}/config",
        #     "headers": api_endpoint['headers'],
        #     "expected_status": 403,
        #     "expected_response": "Access denied"
        # },
        # {
        #     "description": "Improper Inventory Management",
        #     "method": "GET",
        #     "url": f"{api_endpoint['url']}/api_versions",
        #     "headers": api_endpoint['headers'],
        #     "expected_status": 200,
        #     "expected_response": "List of versions"
        # },
        # {
        #     "description": "Unsafe Consumption of APIs",
        #     "method": "POST",
        #     "url": f"{api_endpoint['url']}/consume_third_party",
        #     "headers": api_endpoint['headers'],
        #     "data": {"third_party_url": "http://malicious_service.com"},
        #     "expected_status": 400,
        #     "expected_response": "Bad Request"
        # }
#     ]
#     return advanced_cases

# # 4. Execute Basic Test Cases
# def execute_test_case(api_endpoint):
#     try:
#         url = api_endpoint['url']
#         headers = api_endpoint['headers']
#         response = requests.get(url, headers=headers)
#         return response.status_code, response.text
#     except Exception as e:
#         logging.error(f"Error executing test case for URL {url}: {e}")
#         return None, str(e)

# # 5. Execute Advanced Test Cases
# def execute_advanced_test_case(api_endpoint, test_case):
#     try:
#         url = test_case['url']
#         headers = test_case['headers']
#         data = test_case.get('data', {})
#         if test_case['method'] == 'POST':
#             response = requests.post(url, headers=headers, data=data)
#         else:
#             response = requests.get(url, headers=headers)
#         return response.status_code, response.text
#     except Exception as e:
#         logging.error(f"Error executing advanced test case for URL {url}: {e}")
#         return None, str(e)

# # 6. OWASP ZAP Scanning
# def run_zap_scan(api_endpoints):
#     scan_results = []
#     for endpoint in api_endpoints:
#         url = endpoint['url']
#         try:
#             logging.info(f"Scanning URL: {url}")
            
#             # Access URL
#             zap.urlopen(url)
#             time.sleep(2)  # Wait for the URL to be processed
            
#             # Start Spider
#             logging.info(f"Starting spider scan on {url}")
#             zap.spider.scan(url)
#             while int(zap.spider.status()) < 100:
#                 logging.info(f'Spidering... {zap.spider.status()}%')
#                 time.sleep(2)
#             logging.info('Spider scan completed')
            
#             # Start Active Scan
#             logging.info(f"Starting active scan on {url}")
#             zap.ascan.scan(url)
#             while int(zap.ascan.status()) < 100:
#                 logging.info(f'Active scanning... {zap.ascan.status()}%')
#                 time.sleep(2)
#             logging.info('Active scan completed')
            
#             # Get Alerts
#             alerts = zap.core.alerts(baseurl=url)
#             scan_results.append({'url': url, 'alerts': alerts})
#         except Exception as e:
#             logging.error(f"Error during ZAP scan for URL {url}: {e}")
#             scan_results.append({'url': url, 'alerts': [], 'error': str(e)})
#     return scan_results

# # 7. Analyze Results
# def analyze_results(results, test_cases):
#     vulnerabilities = []
#     for result in results:
#         if 'alerts' in result:
#             for alert in result['alerts']:
#                 vulnerabilities.append({
#                     'test_case': None,
#                     'status': alert['risk'],
#                     'response': alert['description']
#                 })
#     return vulnerabilities

# # 8. Generate Report
# def generate_report(vulnerabilities, test_cases, zap_results):
#     try:
#         with open('report.txt', 'w') as report_file:
#             if vulnerabilities:
#                 for vulnerability in vulnerabilities:
#                     report_file.write(f"Test Case: {vulnerability['test_case']}\n")
#                     report_file.write(f"Status: {vulnerability['status']}\n")
#                     report_file.write(f"Response: {vulnerability['response']}\n")
#                     report_file.write("\n")
            
#             if zap_results:
#                 for result in zap_results:
#                     report_file.write(f"URL: {result['url']}\n")
#                     if 'alerts' in result:
#                         for alert in result['alerts']:
#                             report_file.write(f"Alert: {alert['alert']}\n")
#                     if 'error' in result:
#                         report_file.write(f"Error: {result['error']}\n")
#                     report_file.write("\n")
        
#         # Visualization
#         import matplotlib.pyplot as plt
        
#         status_codes = [v['status'] for v in vulnerabilities]
#         plt.hist(status_codes, bins=range(400, 500, 10), edgecolor='black')
#         plt.xlabel('Status Code')
#         plt.ylabel('Frequency')
#         plt.title('Distribution of HTTP Status Codes for Vulnerabilities')
#         plt.savefig('status_code_distribution.png')
#         plt.close()
        
#         logging.info("Report generated successfully.")
#     except Exception as e:
#         logging.error(f"Error generating report: {e}")

# # 9. Send Notification
# def send_notification(subject, body):
#     import smtplib
#     from email.mime.text import MIMEText

#     msg = MIMEText(body)
#     msg['Subject'] = subject
#     msg['From'] = 'your_email@example.com'
#     msg['To'] = 'recipient@example.com'

#     try:
#         with smtplib.SMTP('smtp.example.com') as server:
#             server.login('your_email@example.com', 'your_password')
#             server.send_message(msg)
#         logging.info("Notification sent successfully.")
#     except Exception as e:
#         logging.error(f"Error sending notification: {e}")

# # 10. Main Function
# def main():
#     import argparse
#     parser = argparse.ArgumentParser(description='API Security Testing Tool')
#     parser.add_argument('--config', type=str, default='api_endpoints.yaml', help='Path to the API endpoints configuration file')
#     parser.add_argument('--scan', action='store_true', help='Run OWASP ZAP scan')
#     parser.add_argument('--generate', action='store_true', help='Generate and execute test cases')
#     args = parser.parse_args()
    
#     try:
#         if args.generate:
#             api_endpoints = load_api_endpoints(args.config)
#             all_test_cases = []
#             for endpoint in api_endpoints:
#                 basic_test_case = generate_test_cases(endpoint)
#                 all_test_cases.append(basic_test_case)
#                 advanced_test_cases = generate_advanced_test_cases(endpoint)
#                 for test_case in advanced_test_cases:
#                     all_test_cases.append(test_case)
            
#             results = [execute_test_case(endpoint) for endpoint in api_endpoints]
#             advanced_results = [execute_advanced_test_case(endpoint, test_case) for endpoint in api_endpoints for test_case in generate_advanced_test_cases(endpoint)]
#             all_results = results + advanced_results
            
#             vulnerabilities = analyze_results(all_results, all_test_cases)
#             generate_report(vulnerabilities, all_test_cases, zap_results)
#             send_notification("API Security Testing Report", "The API security testing has been completed. Check the report for details.")
        
#         if args.scan:
#             api_endpoints = load_api_endpoints(args.config)
#             zap_results = run_zap_scan(api_endpoints)
#             # Add additional scan results handling or reporting if needed

#     except Exception as e:
#         logging.error(f"Unexpected error: {e}")

# if __name__ == '__main__':
#     main()






import yaml
import requests
import logging
from together import Together
from zapv2 import ZAPv2
import time
import argparse

# Configure logging
logging.basicConfig(filename='test_case.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize OWASP ZAP
zap_base_url = 'http://localhost:8080'
zap = ZAPv2(apikey='abc123abc', proxies={'http': zap_base_url, 'https': zap_base_url})

# Initialize Together Client
together_client = Together(api_key="ec9520d163d357d5ed7414ed993c027fdcd36c7d5c64149811fcc85f201db981")

# Define expected responses for each alert type
expected_responses = {
    "Re-examine Cache-control Directives": "The Cache-Control header should be set to ensure proper caching policies.",
    "Cross-Domain Misconfiguration": "Ensure proper CORS (Cross-Origin Resource Sharing) policies are in place.",
    "Server Leaks Version Information via \"Server\" HTTP Response Header Field": "The Server header should not disclose version information.",
    "Strict-Transport-Security Header Not Set": "The Strict-Transport-Security header should be set to enforce HTTPS.",
    "X-Content-Type-Options Header Missing": "The X-Content-Type-Options header should be set to prevent MIME type sniffing.",
    "Server Leaks Information via \"X-Powered-By\" HTTP Response Header Field(s)": "The X-Powered-By header should not disclose server technology information."
}

# 1. Load API Endpoints
def load_api_endpoints(file_path):
    try:
        with open(file_path, 'r') as file:
            data = yaml.safe_load(file)
            logging.info(f"Loaded API Endpoints: {data}")  # Logging instead of print
            return data
    except Exception as e:
        logging.error(f"Error loading API endpoints: {e}")
        raise

# 2. Generate Test Cases using LLM
def generate_test_cases(api_endpoint):
    try:
        response = together_client.chat.completions.create(
            model="meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
            messages=[
                {
                    "role": "system",
                    "content": "You are an API security expert with deep knowledge of OWASP API security risks. Generate realistic test cases for the following risks: Broken Object Level Authorization (BOLA), Broken Authentication, Broken Object Property Level Authorization, Unrestricted Resource Consumption, Broken Function Level Authorization (BFLA), Unrestricted Access to Sensitive Business Flows, Server-Side Request Forgery (SSRF), Security Misconfiguration, Improper Inventory Management. Evaluate the input API for these OWASP Top 10 risks, pass the API through your test cases, and provide a response on whether the API is safe or not safe for each risk in Bold Black letters . Format the output in an aesthetically pleasing table with clear headers and descriptions."
               
                },
                {
                    "role": "user",
                    "content": f"""
                    API URL: {api_endpoint['url']}
                    Headers:
                    {', '.join([f'{key}: {value}' for key, value in api_endpoint['headers'].items()])}
                    """
                }
            ],
            max_tokens=500
        )
        
        test_case_text = response.choices[0].message.content
        logging.info(f"Generated Test Case for URL {api_endpoint['url']}: {test_case_text}")
        return test_case_text
    except Exception as e:
        logging.error(f"Error generating test case: {e}")
        raise

# 3. Generate Advanced Test Cases
def generate_advanced_test_cases(api_endpoint):
    advanced_cases = [
        {
            "description": "SQL Injection Attempt",
            "method": "GET",
            "url": f"{api_endpoint['url']}?id=1' OR '1'='1",
            "headers": api_endpoint['headers'],
            "expected_status": 400,
            "expected_response": "An error message indicating improper input"
        },
        {
            "description": "XSS Attack Attempt",
            "method": "GET",
            "url": f"{api_endpoint['url']}?name=<script>alert('XSS')</script>",
            "headers": api_endpoint['headers'],
            "expected_status": 400,
            "expected_response": "An error message indicating improper input"
        },
        {
            "description": "Large Payload Test",
            "method": "GET",
            "url": f"{api_endpoint['url']}?data={'A'*10000}",
            "headers": api_endpoint['headers'],
            "expected_status": 413,
            "expected_response": "An error message indicating payload too large"
        },
        {
            "description": "Rate Limiting Test",
            "method": "GET",
            "url": f"{api_endpoint['url']}",
            "headers": api_endpoint['headers'],
            "expected_status": 429,
            "expected_response": "An error message indicating rate limit exceeded"
        },
        {
            "description": "Broken Object Level Authorization",
            "method": "GET",
            "url": f"{api_endpoint['url']}/object_level_access",
            "headers": api_endpoint['headers'],
            "expected_status": 403,
            "expected_response": "Access denied"
        },
        {
            "description": "Broken Authentication",
            "method": "POST",
            "url": f"{api_endpoint['url']}/login",
            "headers": api_endpoint['headers'],
            "data": {"username": "admin", "password": "wrong_password"},
            "expected_status": 401,
            "expected_response": "Invalid credentials"
        },
        {
            "description": "Broken Object Property Level Authorization",
            "method": "GET",
            "url": f"{api_endpoint['url']}/object_property",
            "headers": api_endpoint['headers'],
            "expected_status": 403,
            "expected_response": "Access denied"
        },
        {
            "description": "Unrestricted Resource Consumption",
            "method": "GET",
            "url": f"{api_endpoint['url']}/resource_consumption",
            "headers": api_endpoint['headers'],
            "expected_status": 429,
            "expected_response": "Rate limit exceeded"
        },
        {
            "description": "Broken Function Level Authorization",
            "method": "POST",
            "url": f"{api_endpoint['url']}/admin_function",
            "headers": api_endpoint['headers'],
            "data": {"action": "admin_action"},
            "expected_status": 403,
            "expected_response": "Forbidden"
        },
        {
            "description": "Unrestricted Access to Sensitive Business Flows",
            "method": "POST",
            "url": f"{api_endpoint['url']}/sensitive_flow",
            "headers": api_endpoint['headers'],
            "data": {"action": "excessive_use"},
            "expected_status": 403,
            "expected_response": "Access denied"
        },
        {
            "description": "Server Side Request Forgery (SSRF)",
            "method": "POST",
            "url": f"{api_endpoint['url']}/ssrf_vulnerable",
            "headers": api_endpoint['headers'],
            "data": {"url": "http://internal_service:8080"},
            "expected_status": 403,
            "expected_response": "Forbidden"
        },
        {
            "description": "Security Misconfiguration",
            "method": "GET",
            "url": f"{api_endpoint['url']}/config",
            "headers": api_endpoint['headers'],
            "expected_status": 403,
            "expected_response": "Access denied"
        },
        {
            "description": "Improper Inventory Management",
            "method": "GET",
            "url": f"{api_endpoint['url']}/api_versions",
            "headers": api_endpoint['headers'],
            "expected_status": 200,
            "expected_response": "List of versions"
        },
        {
            "description": "Unsafe Consumption of APIs",
            "method": "POST",
            "url": f"{api_endpoint['url']}/consume_third_party",
            "headers": api_endpoint['headers'],
            "data": {"third_party_url": "http://malicious_service.com"},
            "expected_status": 400,
            "expected_response": "Bad Request"
        }
    ]
    return advanced_cases

# 4. Execute Basic Test Cases
def execute_test_case(api_endpoint):
    try:
        url = api_endpoint['url']
        headers = api_endpoint['headers']
        response = requests.get(url, headers=headers)
        return response.status_code, response.text
    except Exception as e:
        logging.error(f"Error executing test case for URL {url}: {e}")
        return None, str(e)

# 5. Execute Advanced Test Cases
def execute_advanced_test_case(api_endpoint, test_case):
    try:
        url = test_case['url']
        headers = test_case['headers']
        data = test_case.get('data', {})
        if test_case['method'] == 'POST':
            response = requests.post(url, headers=headers, data=data)
        else:
            response = requests.get(url, headers=headers)
        return response.status_code, response.text
    except Exception as e:
        logging.error(f"Error executing advanced test case for URL {url}: {e}")
        return None, str(e)

# 6. OWASP ZAP Scanning
def perform_zap_scan(api_file):
    try:
        # Load API Endpoints
        api_endpoints = load_api_endpoints(api_file)

        # Run ZAP Spider
        for api_endpoint in api_endpoints:
            logging.info(f"Starting spider scan on URL {api_endpoint['url']}")
            zap.spider.scan(api_endpoint['url'])
            time.sleep(10)  # Wait for the spider to complete

            # Check Spider Status
            while int(zap.spider.status()) < 100:
                logging.info(f"Spider progress: {zap.spider.status()}%")
                time.sleep(5)

            logging.info(f"Spider scan completed for URL {api_endpoint['url']}")

            # Run ZAP Active Scan
            logging.info(f"Starting active scan on URL {api_endpoint['url']}")
            zap.ascan.scan(api_endpoint['url'])
            while int(zap.ascan.status()) < 100:
                logging.info(f"Active scan progress: {zap.ascan.status()}%")
                time.sleep(5)

            logging.info(f"Active scan completed for URL {api_endpoint['url']}")

        # Generate OWASP ZAP Report
        report_html = zap.core.htmlreport()
        with open('report.txt', 'w') as report_file:
            report_file.write(report_html)
            logging.info("OWASP ZAP report generated")

        # Generate Test Cases
        for api_endpoint in api_endpoints:
            test_case_text = generate_test_cases(api_endpoint)
            with open('test_case.log', 'a') as log_file:
                log_file.write(f"Generated Test Case for {api_endpoint['url']}:\n{test_case_text}\n")

            # Generate Advanced Test Cases
            advanced_cases = generate_advanced_test_cases(api_endpoint)
            for case in advanced_cases:
                status_code, response_text = execute_advanced_test_case(api_endpoint, case)
                logging.info(f"Advanced Test Case - {case['description']} - Status Code: {status_code}, Response: {response_text}")

    except Exception as e:
        logging.error(f"Error performing ZAP scan: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Perform OWASP ZAP scanning and generate test cases.')
    parser.add_argument('api_file', type=str, help='Path to the API endpoints YAML file')

    args = parser.parse_args()

    perform_zap_scan(args.api_file)
