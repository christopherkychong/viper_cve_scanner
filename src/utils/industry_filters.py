"""
Industry-specific keyword filters for healthcare and energy sectors.
Loads keywords from external JSON file for reliability and easy updates.

This module provides the IndustryFilter class which handles:
- Loading keywords from JSON file
- Scoring CVEs based on keyword matches
- Filtering CVEs by industry sector
- Saving updated keywords back to JSON
"""

import json
from pathlib import Path
from typing import List, Dict

# Path to the keywords JSON file - stored in the same directory
KEYWORDS_FILE = Path(__file__).parent / "keywords.json"

class IndustryFilter:
    """
    Filters and scores CVEs based on industry-specific keywords.
    
    The filter loads keywords from a JSON file, allowing users to
    add or remove keywords without modifying code. Keywords are organized
    by sector (healthcare/energy) and category for fine-grained control.
    """
    
    def __init__(self):
        """Initialize the filter by loading keywords from JSON file."""
        self.keywords = self._load_keywords()
    
    def _load_keywords(self) -> Dict:
        """
        Load keywords from the JSON file.
        
        Returns:
            Dictionary containing all sector keywords
            Falls back to default keywords if file is missing or corrupted
        """
        try:
            if KEYWORDS_FILE.exists():
                with open(KEYWORDS_FILE, 'r') as f:
                    return json.load(f)
            else:
                print(f"Warning: Keywords file not found at {KEYWORDS_FILE}")
                return self._get_default_keywords()
        except json.JSONDecodeError as e:
            print(f"Error loading keywords JSON: {e}")
            return self._get_default_keywords()
        except Exception as e:
            print(f"Unexpected error loading keywords: {e}")
            return self._get_default_keywords()
    
    def _get_default_keywords(self) -> Dict:
        """
        Provide fallback keywords when JSON file can't be loaded.
        
        Returns:
            Minimal set of keywords to keep the application functional
        """
        return {
            'healthcare': {
                'medical_devices': ['mri', 'pacemaker', 'ventilator'],
                'healthcare_it': ['ehr', 'emr', 'dicom'],
                'vendors': ['philips', 'medtronic', 'ge'],
                'clinical_context': ['patient', 'hospital', 'clinical']
            },
            'energy': {
                'ot_ics': ['scada', 'plc', 'ics'],
                'infrastructure': ['grid', 'substation', 'pipeline'],
                'vendors': ['siemens', 'schneider', 'rockwell'],
                'components': ['hmi', 'rtu', 'controller']
            }
        }
    
    def save_keywords(self, new_keywords: Dict) -> bool:
        """
        Save updated keywords to the JSON file.
        
        Args:
            new_keywords: Dictionary containing the complete keyword structure
            
        Returns:
            True if save successful, False otherwise
        """
        try:
            with open(KEYWORDS_FILE, 'w') as f:
                json.dump(new_keywords, f, indent=2)
            self.keywords = new_keywords
            return True
        except Exception as e:
            print(f"Error saving keywords: {e}")
            return False
    
    def get_industry_score(self, text: str, industry: str) -> Dict:
        """
        Calculate relevance score for a specific industry based on keyword matches.
        
        Args:
            text: The text to analyze (usually a CVE description)
            industry: Either 'healthcare' or 'energy'
            
        Returns:
            Dictionary containing:
                - industry: The industry analyzed
                - relevance_score: Normalized score (0-10)
                - matches: List of matched keywords with categories
                - match_count: Number of keywords matched
        """
        text_lower = text.lower()
        matches = []
        score = 0
        
        if industry in self.keywords:
            for category, keywords in self.keywords[industry].items():
                for keyword in keywords:
                    if keyword.lower() in text_lower:
                        matches.append({
                            'category': category,
                            'keyword': keyword
                        })
                        # Core categories (medical_devices, ot_ics) weighted higher
                        if category in ['medical_devices', 'ot_ics']:
                            score += 0.5
                        else:
                            score += 0.3
        
        # Normalize score to 0-10 range
        normalized_score = min(10, score * 2)
        
        return {
            'industry': industry,
            'relevance_score': normalized_score,
            'matches': matches,
            'match_count': len(matches)
        }
    
    def get_all_industry_scores(self, text: str) -> Dict:
        """
        Get relevance scores for all industries (healthcare and energy).
        
        Args:
            text: The text to analyze
            
        Returns:
            Dictionary with scores for each industry
        """
        results = {}
        for industry in self.keywords.keys():
            results[industry] = self.get_industry_score(text, industry)
        return results
    
    def filter_by_industry(self, cves: List[Dict], industry: str,
                          threshold: float = 3.0) -> List[Dict]:
        """
        Filter a list of CVEs to only those relevant for a specific industry.
        
        Args:
            cves: List of CVE dictionaries with 'description' fields
            industry: Either 'healthcare' or 'energy'
            threshold: Minimum relevance score to include (default 3.0)
            
        Returns:
            Filtered list of CVEs with industry_relevance added
        """
        filtered = []
        for cve in cves:
            description = cve.get('description', '')
            score_result = self.get_industry_score(description, industry)
            
            if score_result['relevance_score'] >= threshold:
                cve_copy = cve.copy()
                cve_copy['industry_relevance'] = score_result
                filtered.append(cve_copy)
        
        return filtered

# Create a singleton instance for easy importing throughout the application
industry_filter = IndustryFilter()