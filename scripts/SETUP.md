# Setup Instructions

## Getting Your Panther API Credentials

### 1. Find Your Panther Instance URL
Your Panther instance URL is the domain you use to access Panther:
- Format: `https://your-company.panther.com`
- The GraphQL API endpoint will be: `https://api.your-company.panther.com/public/graphql`

### 2. Get Your API Token
1. Log into your Panther console
2. Go to **Settings** → **API Tokens** 
3. Create a new API token with the following permissions:
   - `DataLakeQuery:Read` - Required for executing data lake queries
   - `DataLakeQuery:List` - Optional, for listing queries
4. Copy the generated token

### 3. Configure Environment Variables
1. Copy the example file:
```bash
cp config/.env.example config/.env
```

2. Edit `config/.env` with your values:
```bash
# Your API token from Panther console
PANTHER_API_TOKEN=your_actual_token_here

# Your Panther instance GraphQL endpoint  
PANTHER_API_URL=https://api.your-company.panther.com/public/graphql
```

### 4. Test Your Configuration
Run the data collector to verify your credentials:
```bash
cd scripts/data_collector
python data_collector.py
```

You should see:
- ✅ "Initialized collector with X queries"
- ✅ "API endpoint: https://api.your-company.panther.com/public/graphql"

If you see credential errors, double-check:
- API token is correct and has proper permissions
- API URL matches your Panther instance
- `.env` file is in the correct location (`scripts/config/.env`)

## Common Issues

**"Missing required environment variables"**
- Ensure `.env` file exists in `scripts/config/` directory
- Check that both `PANTHER_API_TOKEN` and `PANTHER_API_URL` are set

**"PANTHER_API_URL must be a valid URL"**
- URL must start with `https://` or `http://`
- Should end with `/public/graphql`

**Authentication errors**
- Verify API token has correct permissions in Panther console
- Ensure token hasn't expired