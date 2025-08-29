#!/usr/bin/env python3
"""
Simple test script to verify Vercel deployment compatibility
"""

import os
import sys
from pathlib import Path

def test_imports():
    """Test that all required modules can be imported"""
    print("Testing imports...")
    
    try:
        from app.models import ScanRequest
        print("✅ app.models imported successfully")
    except Exception as e:
        print(f"❌ Failed to import app.models: {e}")
        return False
    
    try:
        from app.services.orchestrator_vercel import run_full_scan
        print("✅ app.services.orchestrator_vercel imported successfully")
    except Exception as e:
        print(f"❌ Failed to import app.services.orchestrator_vercel: {e}")
        return False
    
    try:
        from app.services.progress import init as progress_init
        print("✅ app.services.progress imported successfully")
    except Exception as e:
        print(f"❌ Failed to import app.services.progress: {e}")
        return False
    
    try:
        from app.services.tools import get_tools_status
        print("✅ app.services.tools imported successfully")
    except Exception as e:
        print(f"❌ Failed to import app.services.tools: {e}")
        return False
    
    return True

def test_paths():
    """Test that all required paths exist"""
    print("\nTesting paths...")
    
    base_dir = Path(__file__).resolve().parent
    required_paths = [
        "templates/index.html",
        "templates/report.html",
        "templates/report_pending.html",
        "static/style.css",
        "api/main.py",
        "vercel.json",
        "requirements.txt",
        "runtime.txt"
    ]
    
    all_exist = True
    for path in required_paths:
        full_path = base_dir / path
        if full_path.exists():
            print(f"✅ {path} exists")
        else:
            print(f"❌ {path} missing")
            all_exist = False
    
    return all_exist

def test_vercel_env():
    """Test Vercel environment detection"""
    print("\nTesting Vercel environment...")
    
    # Simulate Vercel environment
    os.environ['VERCEL'] = '1'
    
    try:
        from api.main import app, REPORTS_DIR
        print(f"✅ Vercel app imported successfully")
        print(f"✅ Reports directory: {REPORTS_DIR}")
        
        # Check if reports directory is set to /tmp in Vercel
        if str(REPORTS_DIR) == '/tmp/reports':
            print("✅ Reports directory correctly set to /tmp/reports for Vercel")
        else:
            print(f"⚠️  Reports directory: {REPORTS_DIR} (should be /tmp/reports in Vercel)")
        
    except Exception as e:
        print(f"❌ Failed to import Vercel app: {e}")
        return False
    
    return True

def main():
    """Run all tests"""
    print("🧪 Testing Vercel deployment compatibility...\n")
    
    tests = [
        test_imports,
        test_paths,
        test_vercel_env
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Your app should deploy successfully to Vercel.")
        return 0
    else:
        print("⚠️  Some tests failed. Please fix the issues before deploying.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
