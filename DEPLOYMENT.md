# Deploying Recon Pro to Vercel

This guide will help you deploy your Recon Pro application to Vercel.

## Prerequisites

1. **Vercel Account**: Sign up at [vercel.com](https://vercel.com)
2. **GitHub/GitLab/Bitbucket**: Your code should be in a Git repository
3. **Vercel CLI** (optional): `npm i -g vercel`

## Important Limitations

⚠️ **Vercel Serverless Functions have limitations:**

- **Execution Time**: Maximum 10 seconds for Hobby plan, 60 seconds for Pro
- **File System**: Read-only except for `/tmp` directory
- **Memory**: Limited memory allocation
- **External Tools**: Most security tools won't be available in serverless environment

## What Works in Vercel

✅ **Passive Reconnaissance**:
- DNS lookups
- WHOIS queries
- SSL certificate analysis
- HTTP header analysis
- Robots.txt fetching
- Certificate Transparency logs

✅ **Python-based Tools**:
- Basic port scanning (Python implementation)
- Directory enumeration (Python requests)
- Vulnerability scanning (Python-based)
- Technology detection

❌ **What Won't Work**:
- External security tools (nmap, nikto, etc.)
- Long-running scans
- Complex network operations
- File-based tools

## Deployment Steps

### 1. Prepare Your Repository

Ensure your repository has these files:
- `vercel.json` - Vercel configuration
- `api/main.py` - Serverless function entry point
- `requirements.txt` - Python dependencies
- `runtime.txt` - Python version specification

### 2. Deploy via Vercel Dashboard

1. Go to [vercel.com](https://vercel.com) and sign in
2. Click "New Project"
3. Import your Git repository
4. Vercel will auto-detect it's a Python project
5. Click "Deploy"

### 3. Deploy via CLI (Alternative)

```bash
# Install Vercel CLI
npm i -g vercel

# Login to Vercel
vercel login

# Deploy from project directory
vercel

# Follow the prompts
```

### 4. Environment Variables (Optional)

If you want AI summaries, add this environment variable in Vercel dashboard:
- `OPENAI_API_KEY`: Your OpenAI API key

## Post-Deployment

### 1. Test Your Deployment

Visit your Vercel URL and test:
- Homepage loads correctly
- Start a simple scan (e.g., `example.com`)
- Check progress updates
- View generated reports

### 2. Monitor Function Logs

In Vercel dashboard:
1. Go to your project
2. Click "Functions" tab
3. Monitor for any errors or timeouts

### 3. Performance Optimization

If you experience timeouts:
- Reduce the number of concurrent scans
- Simplify scan targets
- Consider upgrading to Vercel Pro for longer execution times

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all Python files are properly structured
2. **Timeout Errors**: Reduce scan complexity or upgrade Vercel plan
3. **File System Errors**: All file operations should use `/tmp` directory
4. **Memory Issues**: Optimize code to use less memory

### Debug Mode

To debug locally with Vercel:
```bash
vercel dev
```

This will run your functions locally with Vercel's serverless environment.

## Alternative Deployment Options

For full functionality, consider:

1. **Railway**: Better for long-running processes
2. **Render**: Good for Python applications
3. **DigitalOcean App Platform**: More control over environment
4. **Self-hosted**: Docker deployment for full tool access

## Security Considerations

⚠️ **Important Security Notes**:

- Vercel functions are public by default
- Consider adding authentication
- Be careful with scan targets (avoid unauthorized scanning)
- Monitor usage to avoid rate limiting

## Support

If you encounter issues:
1. Check Vercel function logs
2. Review this deployment guide
3. Check Vercel documentation
4. Consider the limitations mentioned above
