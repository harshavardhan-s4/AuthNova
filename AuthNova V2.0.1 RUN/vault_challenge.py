import hashlib
import requests
import math
import re
from datetime import datetime
from typing import Dict, Any, Tuple

class PasswordStrengthCalculator:
    def __init__(self):
        self.char_sets = {
            'lowercase': len(re.findall(r'[a-z]', '')),
            'uppercase': len(re.findall(r'[A-Z]', '')),
            'numbers': len(re.findall(r'[0-9]', '')),
            'symbols': len(re.findall(r'[^a-zA-Z0-9]', ''))
        }
        
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy"""
        if not password:
            return 0.0
            
        # Count character types
        char_sets = {
            'lowercase': len(re.findall(r'[a-z]', password)),
            'uppercase': len(re.findall(r'[A-Z]', password)),
            'numbers': len(re.findall(r'[0-9]', password)),
            'symbols': len(re.findall(r'[^a-zA-Z0-9]', password))
        }
        
        # Calculate pool size
        pool_size = 0
        if char_sets['lowercase']: pool_size += 26
        if char_sets['uppercase']: pool_size += 26
        if char_sets['numbers']: pool_size += 10
        if char_sets['symbols']: pool_size += 32
        
        return len(password) * math.log2(max(pool_size, 1))

class VaultChallenge:
    def __init__(self):
        self.calculator = PasswordStrengthCalculator()
        self.HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
        
    def _check_hibp(self, password: str) -> int:
        """Check HaveIBeenPwned API using k-anonymity"""
        password_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = password_hash[:5], password_hash[5:]
        
        try:
            response = requests.get(f"{self.HIBP_API_URL}{prefix}")
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for hash_suffix, count in hashes:
                    if hash_suffix == suffix:
                        return int(count)
            return 0
        except Exception as e:
            print(f"HIBP API error: {e}")
            return 0
            
    def _calculate_crack_time(self, entropy: float) -> Tuple[str, float]:
        """Estimate time to crack based on entropy"""
        # Assume 1 billion guesses per second for modern hardware
        guesses = 2 ** entropy
        seconds = guesses / 1_000_000_000
        
        if seconds < 1:
            return "instant", 0
        elif seconds < 60:
            return f"{seconds:.1f} seconds", 0.1
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes", 0.3
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours", 0.5
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days", 0.7
        else:
            return f"{seconds/31536000:.1f} years", 1.0
            
    def _calculate_auth_points(self, entropy: float, crack_time_score: float, breach_count: int) -> int:
        """Calculate Auth Points based on password strength and breach status"""
        base_points = min(100, int(entropy * 2))
        time_bonus = int(crack_time_score * 50)
        breach_penalty = min(base_points, breach_count * 10)
        
        return max(0, base_points + time_bonus - breach_penalty)
        
    def evaluate_password(self, password: str) -> Dict[str, Any]:
        """Main evaluation function returning complete analysis"""
        entropy = self.calculator.calculate_entropy(password)
        breach_count = self._check_hibp(password)
        crack_time, time_score = self._calculate_crack_time(entropy)
        auth_points = self._calculate_auth_points(entropy, time_score, breach_count)
        
        # Determine strength level
        if auth_points >= 90:
            strength = "Exceptional"
        elif auth_points >= 70:
            strength = "Strong"
        elif auth_points >= 50:
            strength = "Moderate"
        else:
            strength = "Weak"
            
        return {
            "strength": strength,
            "auth_points": auth_points,
            "crack_time": crack_time,
            "entropy": round(entropy, 2),
            "breach_count": breach_count,
            "breached": breach_count > 0,
            "feedback": self._generate_feedback(password, entropy, breach_count),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    def _generate_feedback(self, password: str, entropy: float, breach_count: int) -> str:
        """Generate specific feedback for password improvement"""
        feedback = []
        
        if len(password) < 12:
            feedback.append("Consider using at least 12 characters")
        if not re.search(r'[A-Z]', password):
            feedback.append("Add uppercase letters")
        if not re.search(r'[a-z]', password):
            feedback.append("Add lowercase letters")
        if not re.search(r'[0-9]', password):
            feedback.append("Add numbers")
        if not re.search(r'[^a-zA-Z0-9]', password):
            feedback.append("Add special characters")
        if breach_count > 0:
            feedback.append(f"This password appears in {breach_count:,} known breaches")
            
        if not feedback:
            feedback.append("Good job! Your password meets basic security criteria")
            
        return " • ".join(feedback)