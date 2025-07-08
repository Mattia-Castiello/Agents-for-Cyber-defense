import streamlit as st
import asyncio
import os
from typing import Optional, Dict, Any
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- ADK Imports ---
# Core components for agent, model interaction, session management, and execution
from google.adk.agents import Agent
from google.adk.tools import google_search 
from google.adk.models.lite_llm import LiteLlm # Using LiteLLM for flexibility
from google.adk.sessions import InMemorySessionService, Session # In-memory session storage
from google.adk.runners import Runner # Executes agent interactions
from google.genai import types as genai_types # Google AI types (Content, Part)
# Tool and callback related imports
from google.adk.tools.tool_context import ToolContext
from google.adk.agents.callback_context import CallbackContext
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.function_tool import FunctionTool # Helper to wrap Python functions as tools
from google.adk.tools import agent_tool


# Standard Python libraries
import warnings
import logging
import re # Import regex for French detection

# --- Asyncio Configuration for Streamlit ---
# Required to run async ADK functions within Streamlit's synchronous environment
import nest_asyncio
nest_asyncio.apply()

# --- Basic Configuration ---
warnings.filterwarnings("ignore") # Suppress common warnings
logging.basicConfig(level=logging.ERROR) # Reduce log verbosity

# --- Streamlit Page Setup ---
st.set_page_config(page_title="Cybersecurity Triage Assistant", layout="wide")
st.title("🔒 Cybersecurity Triage Assistant with Sub-Agents")
st.caption("AI-powered cybersecurity incident response using Google ADK sub-agents architecture.")

# --- Session State for Modifiable Configs ---
# Initialize default configurations only if they don't exist in Streamlit's session state.
# This allows users to modify them via the UI and have the changes persist across reruns
# until the "Apply Changes" button is clicked.


# Default instruction for the Triage Agent
default_triage_instruction = (
    "You are a Cybersecurity Triage Agent. Your task is to route cybersecurity incidents to the correct specialist sub-agent and present search results properly. "
    "Sub-agents available: "
    "1. The 'phishing_agent' sub-agent: For all questions about phishing, suspicious emails, email security, scams, and social engineering. If the topic involves emails or phishing, **invoke the 'phishing_agent' to provide the final answer.** "
    "2. The 'ransomware_agent' sub-agent: For all questions about ransomware, encrypted files, file recovery, ransom demands, and file-based attacks. If the topic involves ransomware or file encryption, **invoke the 'ransomware_agent' to provide the final answer.** "
    "3. The 'SearchAgent' tool: For all questions about current cybersecurity threats, news, or topics requiring a web search for recent information. Use this tool if the topic requires search. "
    "Analyze the user's query: "
    "- If phishing/email security-related -> **Invoke the 'phishing_agent'.** "
    "- If ransomware/file encryption-related -> **Invoke the 'ransomware_agent'.** "
    "- If current cybersecurity news/search-related -> Use the 'SearchAgent' tool. "
    "- If NONE of these topics, OR a simple greeting/farewell -> Respond ONLY with the exact phrase: 'This service handles Phishing, Ransomware, or Current Cybersecurity Information requests.' "
    "Strictly follow these routing rules. Do not answer cybersecurity questions directly yourself unless you are presenting the result from the SearchAgent tool or relaying the final answer from a sub-agent."
)

# Default instruction for the phishing specialist agent
default_phishing_instruction = (
    "You are the Phishing Agent, an expert in phishing detection and email security. Your goal is to help users identify, respond to, and mitigate phishing attacks. "
    "First, analyze the user's request. Is it a request for general phishing information, detection techniques, or reporting a specific incident? "
    "If YES, you MUST answer the question directly using your own knowledge and expertise. Provide clear guidance on phishing identification, prevention, and response. "
    "Is the request about analyzing a specific phishing incident (email content, suspicious messages, etc.)? "
    "If YES, and ONLY in this specific case, you MUST use the 'analyze_phishing_incident' tool to provide detailed analysis. "
    "DO NOT use the 'analyze_phishing_incident' tool for general phishing questions or educational content. "
    "NEVER delegate a question back to the triage agent or any other agent. You must handle all phishing-related queries given to you, either by answering directly or using the incident analysis tool when appropriate."
)

# Default instruction for the ransomware specialist agent
default_ransomware_instruction = (
    "You are the Ransomware Agent, an expert in ransomware detection, prevention, and recovery. "
    "Your primary role is to answer questions about ransomware (like 'How to prevent ransomware?', 'What to do if infected?', 'How does ransomware spread?') using your own knowledge. "
    "You have a specific tool called 'analyze_ransomware_incident' which can analyze specific ransomware incidents and provide recovery guidance. "
    "ONLY use the 'analyze_ransomware_incident' tool if the user reports a specific ransomware incident (files encrypted, ransom demands, cannot open files). "
    "For ALL other ransomware questions (prevention strategies, general information, recovery methods), answer directly using your expertise. DO NOT use the tool for these. "
    "If the user reports a specific ransomware incident, use the tool and provide the analysis and recovery guidance. "
    "If the tool analysis indicates critical severity, emphasize immediate containment and professional help."
)
# Define default search instruction globally
default_search_instruction = (
    "You are a specialist agent whose ONLY purpose is to use the 'Google Search' tool "
    "to find information related to the user's query. Execute the search based on the query "
    "and return the findings."
)

# --- Session State for Modifiable Configs ---
if "agent_configs" not in st.session_state:
    st.session_state.agent_configs = {
        "triage": {"instruction": default_triage_instruction},
        "phishing": {"instruction": default_phishing_instruction},
        "ransomware": {"instruction": default_ransomware_instruction},
        "search": {"instruction": default_search_instruction}
    }

# (Guardrail config remains the same)
if "guardrail_configs" not in st.session_state:
     st.session_state.guardrail_configs = {
         "blocked_keyword": "FORBIDDEN_WORD",
         "sensitive_info_detection": "enabled"
     }
# --- API Key Configuration ---
# Load API keys securely from Streamlit secrets or environment variables
st.sidebar.header("API Key Configuration")
keys_loaded = False
try:
    # Try loading from Streamlit secrets (recommended for deployment)
    GOOGLE_API_KEY = st.secrets["GOOGLE_API_KEY"]
    OPENAI_API_KEY = st.secrets.get("OPENAI_API_KEY") # Use .get() for optional key
    keys_loaded = True
    # st.sidebar.success("API Keys loaded from Streamlit secrets.")
except (FileNotFoundError, KeyError):
    # Fallback to environment variables (common for local development)
    GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
    if not GOOGLE_API_KEY:
        st.error("🔴 **Error: GOOGLE_API_KEY not found.** Please set it in Streamlit secrets or environment variables.")
        st.stop() # Stop execution if Google key is missing
    if not OPENAI_API_KEY:
         st.warning("🟡 **Warning: OPENAI_API_KEY not found.** Sub-agents using GPT may fail. Set the key or change their model.")
         # Provide a placeholder if missing, so LiteLLM doesn't raise an immediate error if selected
         os.environ["OPENAI_API_KEY"] = "YOUR_OPENAI_API_KEY_PLACEHOLDER"
    else:
        os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY # Ensure env var is set for LiteLLM
        keys_loaded = True
    # st.sidebar.info("API Keys loaded from environment variables.")

# Set environment variables if loaded (needed by ADK/LiteLLM)
if GOOGLE_API_KEY: os.environ["GOOGLE_API_KEY"] = GOOGLE_API_KEY

# Configure ADK to use Google Generative AI APIs directly (not Vertex AI)
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"

# --- Model Constants ---
# Define the models to be used
MODEL_GEMINI_FLASH = "gemini-2.0-flash"
MODEL_GPT_4O = "openai/gpt-4o" # LiteLLM format for OpenAI models

# Display models being used in the sidebar
st.sidebar.markdown("---")
st.sidebar.subheader("Models Used:")
st.sidebar.markdown(f"- **Triage Agent (Root):** `{MODEL_GEMINI_FLASH}`")

# Determine the model for sub-agents based on OpenAI key availability
SUB_AGENT_MODEL_STR = MODEL_GEMINI_FLASH # Default to Gemini
SUB_AGENT_MODEL_OBJ = LiteLlm(model=MODEL_GEMINI_FLASH) # Always use LiteLlm wrapper

if OPENAI_API_KEY and OPENAI_API_KEY != "YOUR_OPENAI_API_KEY_PLACEHOLDER":
    SUB_AGENT_MODEL_STR = MODEL_GPT_4O
    SUB_AGENT_MODEL_OBJ = LiteLlm(model=MODEL_GPT_4O) # Use GPT if key is valid
    st.sidebar.markdown(f"- **Sub Agents (Phishing/Ransomware):** `{SUB_AGENT_MODEL_STR}`")
else:
     st.sidebar.markdown(f"- **Sub Agents (Phishing/Ransomware):** `{SUB_AGENT_MODEL_STR}` (OpenAI key missing/invalid, using Gemini)")

# --- Tool Definitions ---
# Define the Python functions that will act as tools for the agents
# --- Tool Definitions ---

def analyze_phishing_incident(incident_description: str, tool_context: ToolContext) -> dict:
    """
    Analyzes phishing incidents and provides structured response guidance.
    This is a specialized tool for phishing incident management.
    """
    print(f"--- Tool: analyze_phishing_incident executing for incident: '{incident_description}' ---") # DEBUG
    tool_context.state["last_phishing_incident"] = incident_description

    # Basic incident analysis based on keywords
    incident_lower = incident_description.lower().strip()
    
    # Determine severity and initial response
    high_risk_indicators = [
        "clicked link", "entered credentials", "downloaded file", "gave password", 
        "provided credit card", "bank details", "social security", "clicked attachment"
    ]
    
    medium_risk_indicators = [
        "suspicious email", "phishing email", "strange link", "unusual sender",
        "suspicious message", "scam email", "fake email"
    ]
    
    is_high_risk = any(indicator in incident_lower for indicator in high_risk_indicators)
    is_medium_risk = any(indicator in incident_lower for indicator in medium_risk_indicators)
    
    if is_high_risk:
        severity = "HIGH"
        immediate_action = "IMMEDIATE: Disconnect from network, change all passwords, contact IT security immediately"
    elif is_medium_risk:
        severity = "MEDIUM" 
        immediate_action = "Analyze the incident further, avoid clicking any suspicious links"
    else:
        severity = "LOW"
        immediate_action = "Monitor for suspicious activity, verify sender authenticity"
    
    analysis_result = {
        "severity": severity,
        "immediate_action": immediate_action,
        "incident_type": "phishing_analysis",
        "description": incident_description
    }
    
    return {
        "status": "success", 
        "analysis": analysis_result,
        "report": f"Phishing incident analyzed. Severity: {severity}. Immediate action: {immediate_action}"
    }

def analyze_ransomware_incident(incident_description: str, tool_context: ToolContext) -> dict:
    """
    Analyzes ransomware incidents and provides structured response guidance.
    This is a specialized tool for ransomware incident management.
    """
    print(f"--- Tool: analyze_ransomware_incident executing for incident: '{incident_description}' ---") # DEBUG
    tool_context.state["last_ransomware_incident"] = incident_description

    # Basic incident analysis based on keywords
    incident_lower = incident_description.lower().strip()
    
    # Determine severity and initial response
    critical_indicators = [
        "files encrypted", "cannot open files", "ransom note", "payment demand", 
        "files locked", "extension changed", "decrypt", "bitcoin", "crypto", "pay to recover"
    ]
    
    warning_indicators = [
        "suspicious file", "strange behavior", "slow computer", "unusual messages",
        "file corruption", "access denied"
    ]
    
    is_critical = any(indicator in incident_lower for indicator in critical_indicators)
    is_warning = any(indicator in incident_lower for indicator in warning_indicators)
    
    if is_critical:
        severity = "CRITICAL"
        immediate_action = "URGENT: Disconnect from network immediately, do not restart, isolate device, contact IT security"
    elif is_warning:
        severity = "HIGH" 
        immediate_action = "Disconnect from network, backup important data, run security scan"
    else:
        severity = "MEDIUM"
        immediate_action = "Monitor system behavior, backup data, verify file integrity"
    
    analysis_result = {
        "severity": severity,
        "immediate_action": immediate_action,
        "incident_type": "ransomware_analysis",
        "description": incident_description
    }
    
    return {
        "status": "success", 
        "analysis": analysis_result,
        "report": f"Ransomware incident analyzed. Severity: {severity}. Immediate action: {immediate_action}"
    }
    

# --- Callback Definitions ---
# Callbacks allow intercepting and potentially modifying the agent's behavior
# at different points in the execution cycle (before model call, before tool call, etc.).


# --- Before Model Callback ---
def block_keyword_guardrail(
    callback_context: CallbackContext, llm_request: LlmRequest
) -> Optional[LlmResponse]:
    """
    Inspects the latest user message for a configured blocked keyword BEFORE sending to the LLM.
    Includes DEBUG print statements.
    """
    agent_name = callback_context.agent_name
    last_user_message_text = ""

    if llm_request.contents:
        for content in reversed(llm_request.contents):
            if content.role == 'user' and content.parts:
                part_text = getattr(content.parts[0], 'text', None)
                if part_text:
                    last_user_message_text = part_text
                    break

    keyword_to_block = st.session_state.guardrail_configs.get("blocked_keyword", "").strip().upper()

    # --- DEBUG PRINT STATEMENTS ---
    print(f"\n--- DEBUG [Callback]: Entering block_keyword_guardrail for agent {agent_name} ---")
    print(f"--- DEBUG [Callback]: Last user message: '{last_user_message_text}' ---")
    print(f"--- DEBUG [Callback]: Keyword to block: '{keyword_to_block}' ---")
    # --- END DEBUG ---

    if keyword_to_block and keyword_to_block in last_user_message_text.upper():
        print(f"--- DEBUG [Callback]: Keyword found! Blocking. ---") # DEBUG
        # st.warning(f"Guardrail triggered: Blocked keyword '{keyword_to_block}' found in input for {agent_name}.") # Optional UI feedback
        callback_context.state["guardrail_block_keyword_triggered"] = True
        return LlmResponse(
            content=genai_types.Content(
                role="model",
                parts=[genai_types.Part(text=f"I cannot process this request because it contains the blocked keyword '{keyword_to_block}'.")],
            )
        )
    else:
        print(f"--- DEBUG [Callback]: Keyword not found. Allowing. ---") # DEBUG
        callback_context.state["guardrail_block_keyword_triggered"] = False
        return None

# --- Before Tool Callback ---
def block_sensitive_info_in_phishing_tool_guardrail(
    tool: BaseTool, args: Dict[str, Any], tool_context: ToolContext
) -> Optional[Dict]:
    """
    Checks if the 'analyze_phishing_incident' tool is being called with sensitive information
    that should be handled carefully (like credit card numbers, SSN, etc.).
    Includes DEBUG print statements.
    """
    tool_name = tool.name
    agent_name = tool_context.agent_name

    target_tool_name = "analyze_phishing_incident"
    
    # --- DEBUG PRINT STATEMENTS ---
    print(f"\n--- DEBUG [Callback]: Entering block_sensitive_info_in_phishing_tool_guardrail for agent {agent_name}, tool {tool_name} ---")
    # --- END DEBUG ---

    # Only apply this guardrail to the specified tool
    if tool_name == target_tool_name:
        print(f"--- DEBUG [Callback]: Checking tool {target_tool_name} for sensitive information. ---") # DEBUG
        incident_description = args.get("incident_description", "").lower()
        print(f"--- DEBUG [Callback]: Incident description received by tool: '{incident_description}' ---") # DEBUG

        # Check for potential sensitive information patterns
        sensitive_patterns = [
            r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # Credit card pattern
            r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',  # SSN pattern
            r'\bpassword\s*[:=]\s*\w+',  # Password patterns
            r'\bpin\s*[:=]\s*\d+',  # PIN patterns
        ]
        
        contains_sensitive = False
        for pattern in sensitive_patterns:
            if re.search(pattern, incident_description):
                contains_sensitive = True
                break
        
        print(f"--- DEBUG [Callback]: Sensitive information detected: {contains_sensitive} ---") # DEBUG

        if contains_sensitive:
            print(f"--- DEBUG [Callback]: Sensitive information detected! Providing warning. ---") # DEBUG
            tool_context.state["guardrail_sensitive_info_warning"] = True
            return {
                "status": "warning",
                "message": "WARNING: Potential sensitive information detected. For your security, avoid sharing complete credit card numbers, passwords, or PIN codes. I can still help with the phishing incident analysis."
            }
        else:
             print(f"--- DEBUG [Callback]: No sensitive information detected. Allowing tool call. ---") # DEBUG
             tool_context.state["guardrail_sensitive_info_warning"] = False
    else:
         print(f"--- DEBUG [Callback]: Guardrail not applicable (Tool: '{tool_name}'). Allowing tool call. ---") # DEBUG
         tool_context.state["guardrail_sensitive_info_warning"] = False

    return None

# --- Agent Definitions ---
# Define the agents, including their models, instructions, tools, and sub-agents.
# Use @st.cache_resource to cache agent instances. They are only recreated when
# the cache is explicitly cleared (e.g., by the "Apply Changes" button).
# --- Agent Definitions ---
# Current Affairs Agent ---
@st.cache_resource
def create_search_agent():
    """Creates the Search Agent which uses the Google Search tool."""
    # Use a distinct name for the instruction in session state
    config_key = "search" # Changed from current_affairs
    default_instruction = ( # Define default here or load from main config dict
         "You are a specialist agent whose ONLY purpose is to use the 'Google Search' tool "
         "to find information related to the user's query. Execute the search based on the query "
         "and return the findings."
    )
    # Ensure config exists in session state
    if config_key not in st.session_state.agent_configs:
         st.session_state.agent_configs[config_key] = {"instruction": default_instruction}

    print(f"--- DEBUG: Attempting to create {config_key}_agent ---")
    try:
        instruction = st.session_state.agent_configs[config_key]["instruction"]
        agent = Agent(
            # Use a Gemini model compatible with Google Search
            # Using MODEL_GEMINI_FLASH ("gemini-1.5-flash-latest") as it's known to work
            # Or use "gemini-2.0-flash" if preferred and available
            model="gemini-2.0-flash",
            name='SearchAgent', # Use the name from the example/docs
            instruction=instruction,
            description="A specialist agent that performs Google searches for current events or specific information.",
            tools=[google_search], # Assign the built-in Google Search tool
        )
        print(f"--- DEBUG: {config_key}_agent created. Model: {agent.model}. Tools registered: {[tool.name for tool in agent.tools] if agent.tools else 'None'} ---")
        return agent
    except Exception as e:
        st.error(f"Fatal Error creating Search Agent: {e}. Check model name and instruction.")
        st.stop()


# --- Phishing Agent ---
@st.cache_resource
def create_phishing_agent():
    """Creates the Phishing Agent using instruction from session state."""
    print("--- DEBUG: Attempting to create phishing_agent ---")
    try:
        instruction = st.session_state.agent_configs["phishing"]["instruction"]
        agent = Agent(
            model=SUB_AGENT_MODEL_OBJ,
            name="phishing_agent",
            instruction=instruction,
            description="Handles phishing incidents, email security, and social engineering questions.",
            tools=[FunctionTool(analyze_phishing_incident)],
            before_tool_callback=block_sensitive_info_in_phishing_tool_guardrail
        )
        print(f"--- DEBUG: phishing_agent created. Tools registered: {[tool.name for tool in agent.tools] if agent.tools else 'None'} ---")
        return agent
    except Exception as e:
        st.error(f"Fatal Error creating Phishing Agent: {e}. Check API keys, model name '{SUB_AGENT_MODEL_STR}', and instruction.")
        st.stop()

@st.cache_resource
def create_ransomware_agent():
    """Creates the Ransomware Agent using instruction from session state."""
    print("--- DEBUG: Attempting to create ransomware_agent ---")
    try:
        instruction = st.session_state.agent_configs["ransomware"]["instruction"]
        agent = Agent(
            model=SUB_AGENT_MODEL_OBJ,
            name="ransomware_agent",
            instruction=instruction,
            description="Handles ransomware incidents, file encryption attacks, and recovery guidance.",
            tools=[FunctionTool(analyze_ransomware_incident)],
            # No specific callback needed for ransomware agent
        )
        print(f"--- DEBUG: ransomware_agent created. Tools registered: {[tool.name for tool in agent.tools] if agent.tools else 'None'} ---")
        return agent
    except Exception as e:
        st.error(f"Fatal Error creating Ransomware Agent: {e}. Check API keys, model name '{SUB_AGENT_MODEL_STR}', and instruction.")
        st.stop()

@st.cache_resource
def create_triage_agent(_phishing_agent, _ransomware_agent, _search_agent):
    """Creates the Root Triage Agent (Hybrid: Sub-Agents + AgentTool)."""
    print("--- DEBUG: Attempting to create triage_agent (Hybrid version) ---")
    if not _phishing_agent or not _ransomware_agent or not _search_agent:
        st.error("Cannot create Triage Agent, one or more required agents are not available.")
        st.stop()
    try:
        instruction = st.session_state.agent_configs["triage"]["instruction"]

        agent = Agent(
            name="triage_agent_hybrid_router",
            model=MODEL_GEMINI_FLASH,
            description="Router agent that delegates to Phishing/Ransomware sub-agents or uses a Search agent tool.",
            instruction=instruction,

            # --- Keep Phishing/Ransomware as sub_agents ---
            sub_agents=[_phishing_agent, _ransomware_agent],

            # --- Add SearchAgent via AgentTool ---
            tools=[
                agent_tool.AgentTool(agent=_search_agent)
            ],

            output_key="last_agent_response",
            # Keyword callback remains on the root agent
            before_model_callback=block_keyword_guardrail,
        )
        print(f"--- DEBUG: triage_agent_hybrid_router created. Sub-agents: {[sub.name for sub in agent.sub_agents] if agent.sub_agents else 'None'}. Tools: {[tool.name for tool in agent.tools] if agent.tools else 'None'} ---")
        return agent
    except Exception as e:
        st.error(f"Fatal Error creating Triage Agent: {e}. Check model name '{MODEL_GEMINI_FLASH}' and instruction.")
        st.stop()

# --- Create agent instances ---
# This will use cached versions unless the cache has been cleared.
phishing_agent = create_phishing_agent()
ransomware_agent = create_ransomware_agent()
search_agent = create_search_agent() # Create the search agent instance
# Pass all three specialist agents to the triage agent creator
root_triage_agent = create_triage_agent(phishing_agent, ransomware_agent, search_agent)


# --- Initialize ADK Runner and Session Service ---
@st.cache_resource # Cache the runner and session service infrastructure
def initialize_adk_infra(_root_agent):
    """Initializes ADK Runner and Session Service."""
    if not _root_agent:
        st.error("Cannot initialize ADK Infra, Root Agent not available.")
        st.stop()

    # Use a simple in-memory session service for this example
    session_service = InMemorySessionService()

    # Define identifiers for the application and user/session
    app_name = "streamlit_tutor_app_editable"
    user_id = "streamlit_user_tutor"
    session_id = "streamlit_session_tutor"
    # Initial state for the session (can be empty or contain starting values)
    initial_state = {"user_preference_language": "English"} # Example state variable

    try:
        # Create the initial session in the session service
        adk_session = session_service.create_session(
            app_name=app_name, user_id=user_id, session_id=session_id, state=initial_state
        )
        st.sidebar.write(f"🔑 ADK Session '{session_id}' created.")
    except Exception as e:
        st.error(f"Fatal Error creating ADK session: {e}")
        st.stop()

    try:
        # Create the Runner, linking the root agent and session service
        runner = Runner(agent=_root_agent, app_name=app_name, session_service=session_service)
        st.sidebar.write("✅ ADK Runner Initialized.") # Indicate readiness
        # Return components needed elsewhere in the app
        return {
            "runner": runner, "session_service": session_service,
            "app_name": app_name, "user_id": user_id, "session_id": session_id
        }
    except Exception as e:
        st.error(f"Fatal Error creating ADK Runner: {e}")
        st.stop()

# --- Get ADK infrastructure components ---
# This uses the cached infrastructure unless cleared.
adk_infra = initialize_adk_infra(root_triage_agent)
runner = adk_infra["runner"]
session_service = adk_infra["session_service"]
app_name = adk_infra["app_name"]
user_id = adk_infra["user_id"]
session_id = adk_infra["session_id"]

# --- Sidebar Configuration UI ---
# Allow users to modify agent instructions and guardrail parameters
st.sidebar.markdown("---")
st.sidebar.header("⚙️ Configuration")

# Button to apply changes: Clears caches and resets chat
st.sidebar.info("Modify settings below and click Apply to rebuild agents.")
if st.sidebar.button("Apply Changes & Reset Chat", key="apply_changes"):
    # Clear the caches for agents and infrastructure to force recreation
    create_phishing_agent.clear()
    create_ransomware_agent.clear()
    create_search_agent.clear()
    create_triage_agent.clear()
    initialize_adk_infra.clear()

    # Reset chat history in Streamlit's session state
    st.session_state.messages = []

    st.sidebar.success("Configuration applied! Caches cleared & chat reset.")
    st.toast("Agents rebuilt with new configuration!")
    # Force a rerun of the Streamlit script to pick up changes and rebuild
    st.rerun()

# Expanders for editing configurations stored in st.session_state
with st.sidebar.expander("Agent Instructions", expanded=False):
     # Text area for root Triage Agent instruction
     st.session_state.agent_configs["triage"]["instruction"] = st.text_area(
        "Triage Agent (Root) Instruction",
        value=st.session_state.agent_configs["triage"]["instruction"],
        height=250,
        key="triage_instruction_input"
    )
     # Text area for Phishing Agent instruction
     st.session_state.agent_configs["phishing"]["instruction"] = st.text_area(
        "Phishing Agent Instruction",
        value=st.session_state.agent_configs["phishing"]["instruction"],
        height=150,
        key="phishing_instruction_input"
    )
     # Text area for Ransomware Agent instruction
     st.session_state.agent_configs["ransomware"]["instruction"] = st.text_area(
        "Ransomware Agent Instruction",
        value=st.session_state.agent_configs["ransomware"]["instruction"],
        height=150,
        key="ransomware_instruction_input"
    )
     # Text area for Search Agent instruction
     st.session_state.agent_configs["search"]["instruction"] = st.text_area(
        "Search Agent Instruction",
        value=st.session_state.agent_configs["search"]["instruction"],
        height=150,
        key="search_instruction_input"
     )

# Expander for guardrail parameters
with st.sidebar.expander("Guardrail Parameters", expanded=False):
    # Input for the blocked keyword (model input guardrail)
    st.session_state.guardrail_configs["blocked_keyword"] = st.text_input(
        "Keyword to Block (Model Input Guardrail)",
        value=st.session_state.guardrail_configs["blocked_keyword"],
        key="blocked_keyword_input"
    )
    # Input for sensitive info detection (tool input guardrail - Phishing tool)
    st.session_state.guardrail_configs["sensitive_info_detection"] = st.selectbox(
        "Sensitive Info Detection (Tool Input Guardrail - Phishing Tool)",
        options=["enabled", "disabled"],
        index=0 if st.session_state.guardrail_configs["sensitive_info_detection"] == "enabled" else 1,
        key="sensitive_info_detection_input"
    )

# --- Chat History Initialization ---
# Initialize the chat message history in Streamlit's session state if it doesn't exist
if "messages" not in st.session_state:
    st.session_state.messages = [] # Stores messages as {"role": "user/assistant", "content": "..."}

# --- Display Chat History ---
# Iterate through the stored messages and display them using Streamlit's chat elements
for message in st.session_state.messages:
    with st.chat_message(message["role"]): # "user" or "assistant"
        st.markdown(message["content"], unsafe_allow_html=True) # Display content (allow basic HTML for formatting)

# --- Agent Interaction Logic ---
async def get_agent_response(user_query: str) -> tuple[str, str]:
    """
    Sends the user query to the ADK runner and processes the asynchronous events
    to extract the final response text and the name of the agent that produced it.
    """
    # Create the user message content in the format expected by ADK
    content = genai_types.Content(role='user', parts=[genai_types.Part(text=user_query)])

    # Initialize default response values
    final_response_text = "Agent did not produce a final response."
    final_response_author = "system" # Default author if none is found

    try:
        # Asynchronously iterate through events generated by the runner
        async for event in runner.run_async(user_id=user_id, session_id=session_id, new_message=content):
            # Check if the event is the final response from an agent
            if event.is_final_response():
                final_response_author = event.author if event.author else "unknown_agent" # Get the agent's name

                # Extract text content from the response parts
                if event.content and event.content.parts:
                    text_parts = [getattr(part, 'text', '') for part in event.content.parts if hasattr(part, 'text')]
                    final_response_text = " ".join(filter(None, text_parts)) # Join non-empty text parts
                    if not final_response_text: # Handle case where parts exist but have no text
                         final_response_text = "(Agent returned empty text content)"

                # Handle cases where the final event indicates an error or specific action
                elif event.error_message:
                    final_response_text = f"Agent Error: {event.error_message}"
                    final_response_author = event.author if event.author else "error_handler"
                elif event.actions and event.actions.escalate:
                     final_response_text = f"Action Required: Escalated. Reason: {event.error_message or 'None specified'}"
                     final_response_author = event.author if event.author else "escalation_handler"
                # Fallback if none of the above conditions extracted text
                elif final_response_text == "Agent did not produce a final response.":
                     final_response_text = "(Final response received with no displayable content or error)"

                break # Stop processing events once the final response is found
    except Exception as e:
        # Catch errors during the agent execution
        st.error(f"An error occurred during agent interaction: {e}")
        final_response_text = f"Sorry, a critical error occurred: {e}"
        final_response_author = "system_error"

    # Clean up the author name (sometimes ADK might provide a longer identifier)
    if isinstance(final_response_author, str):
         final_response_author = final_response_author.split('.')[-1] # Get the last part (agent name)

    return final_response_text, final_response_author

# --- Handle User Input ---
# Get input from the user via Streamlit's chat input widget
if prompt := st.chat_input("Describe your cybersecurity issue (e.g., 'I received a suspicious email', 'My files are encrypted', 'Latest ransomware trends')..."):
    # 1. Add user message to Streamlit's history and display it
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # 2. Show a spinner while waiting for the agent's response
    with st.spinner("Thinking..."):
        # 3. Call the async function to get the agent response
        # asyncio.run is used here because Streamlit runs synchronously
        response_text, agent_name = asyncio.run(get_agent_response(prompt))

        # Format the response to include the agent's name
        display_response = f"**[{agent_name}]** {response_text}"

        # 4. Add the assistant's response to Streamlit's history and display it
        st.session_state.messages.append({"role": "assistant", "content": display_response})
        with st.chat_message("assistant"):
            st.markdown(display_response, unsafe_allow_html=True)

# --- Display Current ADK Session State and History ---
# This section runs after every interaction to show the internal state of the ADK session.
st.sidebar.markdown("---")
st.sidebar.header("📊 Session Data")
try:
    # Retrieve the current ADK session object from the session service
    current_adk_session: Optional[Session] = session_service.get_session(
        app_name=app_name,
        user_id=user_id,
        session_id=session_id
    )

    # Check if the session was retrieved successfully
    if current_adk_session:

        # --- Section 1: Display Session State ---
        st.sidebar.write("**Current State:**") # Header for state section
        state_dict = current_adk_session.state # Access the state dictionary

        # Display relevant state variables set by tools or callbacks
        st.sidebar.write(f"- User Pref Lang: `{state_dict.get('user_preference_language', 'N/A')}`")
        st.sidebar.write(f"- Last Phishing Incident: `{state_dict.get('last_phishing_incident', 'N/A')}`")
        st.sidebar.write(f"- Last Ransomware Incident: `{state_dict.get('last_ransomware_incident', 'N/A')}`")
        # Display guardrail trigger status
        model_kw_triggered = state_dict.get('guardrail_block_keyword_triggered', 'N/A')
        sensitive_info_warning = state_dict.get('guardrail_sensitive_info_warning', 'N/A')
        st.sidebar.write(f"- Model KW Guardrail Triggered: `{model_kw_triggered}`")
        st.sidebar.write(f"- Sensitive Info Warning: `{sensitive_info_warning}`")

        # Expander to show the raw state dictionary for debugging
        with st.sidebar.expander("Raw State Dictionary", expanded=False):
             st.json(state_dict if state_dict else {"state": "empty"})
        # --- End Section 1 ---


        # --- Section 2: Display Session History (from Events) ---
        # Access the event history stored within the Session object
        session_events = getattr(current_adk_session, 'events', None) # Use getattr for safe access

        if session_events is not None and isinstance(session_events, list):
            # Display events inside an expander
            with st.sidebar.expander(f"Detailed Event History ({len(session_events)} events)", expanded=True):
                 if session_events:
                     # Loop through each event object in the history
                     for i, event_obj in enumerate(session_events):
                         # --- Extract relevant info from the event object safely using getattr ---
                         author = getattr(event_obj, 'author', 'unknown_author')
                         role = getattr(event_obj, 'role', None) # Role might not always be present
                         display_actor = f"{author}" + (f" (Role: {role})" if role else "") # Combine author and role if available

                         content_obj = getattr(event_obj, 'content', None)
                         parts_text = []
                         function_calls = []
                         function_responses = []

                         # --- Safely extract details from content parts ---
                         if content_obj and getattr(content_obj, 'parts', None):
                            for part in content_obj.parts:
                                # Try getting different payload types
                                fc = getattr(part, 'function_call', None)
                                fr = getattr(part, 'function_response', None)
                                pt = getattr(part, 'text', None)

                                # Append extracted info to respective lists
                                if fc:
                                    fc_name = getattr(fc, 'name', '(unknown func)')
                                    fc_args = getattr(fc, 'args', {})
                                    function_calls.append(f"Tool Call: {fc_name}({fc_args})")
                                elif fr:
                                    fr_name = getattr(fr, 'name', '(unknown func)')
                                    fr_response = getattr(fr, 'response', {})
                                    # Truncate long responses for display
                                    response_str = f"{fr_response}"
                                    if len(response_str) > 150:
                                        response_str = response_str[:150] + "..."
                                    function_responses.append(f"Tool Resp: {fr_name} -> {response_str}")
                                elif pt:
                                    parts_text.append(pt)

                         # --- Display formatted event information ---
                         st.markdown(f"**{i+1}. By:** `{display_actor}`")
                         if parts_text:
                             st.text("Text: " + " ".join(parts_text))
                         if function_calls:
                             st.text(" ".join(function_calls))
                         if function_responses:
                             st.text(" ".join(function_responses))

                         # Display the type of event (e.g., LlmRequestEvent, ToolRequestEvent)
                         event_type = getattr(event_obj, '__class__', None)
                         if event_type:
                             st.caption(f"Event Type: {event_type.__name__}")

                         # --- Optional Raw Event Data for Debugging ---
                         # with st.expander("Raw Event Data (DEBUG)", expanded=False):
                         #     st.write(event_obj)
                         # --- End Raw Event Data ---

                         st.markdown("---") # Separator between events
                 else:
                     st.write("Session event list is empty.")
        else:
             st.write("Could not find a valid 'events' list on the session object.")
        # --- End Section 2 ---

    else:
        # Warning if the session object couldn't be found
        st.sidebar.warning(f"ADK Session '{session_id}' not found in the service.")

# Catch potential errors during session data access or display
except AttributeError as ae:
     st.sidebar.error(f"Error accessing session attributes: {ae}. Session structure might be unexpected.")
except Exception as e:
    st.sidebar.error(f"Error retrieving/displaying session data: {e}")
    # import traceback # Uncomment for detailed debugging
    # st.sidebar.text(traceback.format_exc()) # Uncomment for detailed debugging