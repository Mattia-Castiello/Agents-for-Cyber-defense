# 🔒 Cybersecurity Triage Assistant

An AI-powered cybersecurity incident response system built with Google ADK (Agent Development Kit) and Streamlit. This application uses a multi-agent architecture with specialized sub-agents to handle different types of cybersecurity incidents.

## 🌟 Features

- **Multi-Agent Architecture**: Intelligent routing to specialized agents
- **Phishing Detection**: Dedicated agent for email security and phishing incidents
- **Ransomware Response**: Specialized agent for ransomware incidents and recovery
- **Real-time Search**: Current cybersecurity threat intelligence via Google Search
- **Advanced Guardrails**: Built-in security measures and sensitive data protection
- **Configurable Instructions**: Customizable agent behaviors through the UI
- **Session Management**: Persistent conversation history and state tracking

## 🏗️ Architecture

### Main Components

1. **Triage Agent (Root)**: Routes queries to appropriate specialist agents
2. **Phishing Agent**: Handles email security, phishing detection, and social engineering
3. **Ransomware Agent**: Manages ransomware incidents, file encryption, and recovery
4. **Search Agent**: Provides real-time cybersecurity threat intelligence

### Tools

- **analyze_phishing_incident**: Structured phishing incident analysis
- **analyze_ransomware_incident**: Ransomware incident assessment and response
- **Google Search**: Real-time cybersecurity information retrieval

### Guardrails

- **Keyword Blocking**: Prevents processing of blocked terms
- **Sensitive Information Detection**: Protects against exposure of sensitive data in phishing analysis

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Google API Key (for Gemini models and Google Search)
- OpenAI API Key (optional, for GPT models)

### Installation

1. **Clone or download the project:**

2. **Create and activate virtual environment:**
   ```bash
   python -m venv cybertriageenv
   source cybertriageenv/bin/activate  # On macOS/Linux
   # or
   cybertriageenv\Scripts\activate     # On Windows
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Configuration

Set up your API keys using one of these methods:

#### Option 1: Environment Variables
```bash
export GOOGLE_API_KEY="your_google_api_key_here"
export OPENAI_API_KEY="your_openai_api_key_here"  # Optional
```

#### Option 2: Streamlit Secrets
Create `.streamlit/secrets.toml`:
```toml
GOOGLE_API_KEY = "your_google_api_key_here"
OPENAI_API_KEY = "your_openai_api_key_here"  # Optional
```

### Running the Application

```bash
cd "/path/of/the/fold" && streamlit run /path/ of/cybersecurityTriageAgent.py
```

Alternative command (if using the original demo path):
```bash
cd "/Users/mattiacastiello/Desktop/cyber_agents/cybertriageenv" && streamlit run "/Users/mattiacastiello/Desktop/cyber_agents/cybersecurityTriageAgent.py"
```

The application will open in your default web browser at `http://localhost:8501`

## 📖 Usage Examples

### Phishing Incidents
- "I received a suspicious email from my bank asking for login details"
- "Someone is impersonating our CEO in emails"
- "How can I identify phishing emails?"

### Ransomware Incidents
- "My files are encrypted and I see a ransom note"
- "All my documents have strange extensions and I can't open them"
- "How to prevent ransomware attacks?"

### Current Threat Intelligence
- "What are the latest cybersecurity threats this week?"
- "Recent phishing campaigns targeting financial institutions"
- "Latest ransomware variants and their indicators"

## ⚙️ Configuration

### Agent Instructions
Use the sidebar to customize agent behaviors:
- **Triage Agent**: Modify routing logic and response patterns
- **Phishing Agent**: Adjust phishing detection and response strategies
- **Ransomware Agent**: Configure incident analysis and recovery guidance
- **Search Agent**: Customize search behavior and result formatting

### Guardrails
- **Keyword Blocking**: Set words/phrases to block from processing
- **Sensitive Info Detection**: Toggle protection for credit cards, SSN, passwords

### Models
- **Default**: Gemini 2.0 Flash for all agents
- **With OpenAI Key**: GPT-4o for sub-agents, Gemini for triage and search

## 🔧 Technical Details

### Dependencies
- **streamlit**: Web application framework
- **google-adk**: Google Agent Development Kit
- **litellm**: Multi-provider LLM interface
- **nest-asyncio**: Async support in Streamlit
- **google-generativeai**: Google AI integration

### Session Management
- In-memory session storage for conversation history
- State tracking for incident analysis and guardrail triggers
- Event history for debugging and audit trails

### Error Handling
- Graceful API key validation
- Model fallback mechanisms
- Comprehensive error logging and user feedback

## 🛡️ Security Features

1. **Input Validation**: Keyword blocking and content filtering
2. **Sensitive Data Protection**: Automatic detection and warnings
3. **Secure API Key Management**: Environment variables and Streamlit secrets
4. **Session Isolation**: Per-user session state management

## 🐛 Troubleshooting

### Common Issues

1. **API Key Errors**:
   - Verify your Google API key is valid and has the necessary permissions
   - Check if you're using the correct environment variable names

2. **Model Not Found**:
   - Ensure you have access to the specified models
   - Try switching to different model variants in the code

3. **Import Errors**:
   - Verify all dependencies are installed: `pip install -r requirements.txt`
   - Check if you're in the correct virtual environment

4. **Port Already in Use**:
   - Use a different port: `streamlit run cybersecurityTriageAgent.py --server.port 8502`

## 📊 Monitoring

The application provides real-time monitoring through the sidebar:
- **Session State**: Current conversation context and variables
- **Event History**: Detailed interaction logs
- **Guardrail Status**: Security measure activation tracking
- **Agent Activity**: Which agents handled which requests

## 🔄 Updates and Maintenance

To update agent configurations:
1. Modify instructions in the sidebar
2. Click "Apply Changes & Reset Chat"
3. Agents will be rebuilt with new configurations

## 📄 License

This project is part of the Google ADK demos and follows the associated licensing terms.

## 🤝 Contributing

This is a demonstration project. For improvements or issues:
1. Document the problem or enhancement
2. Test changes thoroughly
3. Ensure all security features remain functional

## 📞 Support

For technical issues:
- Check the error messages in the Streamlit interface
- Review the session data in the sidebar for debugging information
- Verify API key permissions and quotas

---

**Note**: This application is designed for educational and demonstration purposes. For production cybersecurity incident response, implement additional security measures and professional incident response procedures.
