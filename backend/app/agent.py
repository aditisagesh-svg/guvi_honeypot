"""
Honey-Pot Agent FSM Module
Finite State Machine for conversation strategy during scam interaction
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional, Callable
from datetime import datetime


class AgentState(str, Enum):
    """FSM states for honey-pot conversation strategy"""
    IDLE = "IDLE"
    CONFUSE = "CONFUSE"
    DELAY = "DELAY"
    EXTRACT = "EXTRACT"
    SAFE_EXIT = "SAFE_EXIT"


class Event(str, Enum):
    """Events that trigger state transitions"""
    NEW_MESSAGE = "NEW_MESSAGE"
    HIGH_RISK_DETECTED = "HIGH_RISK_DETECTED"
    MEDIUM_RISK_DETECTED = "MEDIUM_RISK_DETECTED"
    LOW_RISK_DETECTED = "LOW_RISK_DETECTED"
    ENTITY_EXTRACTED = "ENTITY_EXTRACTED"
    SCAMMER_ANGRY = "SCAMMER_ANGRY"
    TIMEOUT = "TIMEOUT"
    MANUAL_EXIT = "MANUAL_EXIT"


@dataclass
class AgentContext:
    """Context maintained throughout the conversation"""
    session_id: str
    messages: List[Dict[str, str]]
    extracted_intelligence: List[Dict]
    state: AgentState
    entry_time: datetime
    message_count: int
    risk_history: List[float]

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.messages = []
        self.extracted_intelligence = []
        self.state = AgentState.IDLE
        self.entry_time = datetime.utcnow()
        self.message_count = 0
        self.risk_history = []


class Transition:
    """Defines a state transition"""

    def __init__(
        self,
        from_state: AgentState,
        event: Event,
        to_state: AgentState,
        action: Optional[Callable] = None
    ):
        self.from_state = from_state
        self.event = event
        self.to_state = to_state
        self.action = action


class HoneyPotAgent:
    """
    Finite State Machine for managing honey-pot conversation strategy.

    States:
    - IDLE: Waiting for initial message
    - CONFUSE: Responding with confusing/non-sequitur messages
    - DELAY: Stalling with excuses to waste scammer time
    - EXTRACT: Actively gathering intelligence about the scammer
    - SAFE_EXIT: Preparing to end conversation safely

    Transitions are triggered by events like risk level changes,
    message patterns, and extracted entities.
    """

    def __init__(self):
        """Initialize FSM with all possible transitions"""
        self.transitions: List[Transition] = self._create_transitions()
        self.contexts: Dict[str, AgentContext] = {}

    def _create_transitions(self) -> List[Transition]:
        """Create all state transitions"""
        return [
            # IDLE transitions
            Transition(
                AgentState.IDLE, Event.NEW_MESSAGE,
                AgentState.DELAY,
                self._on_enter_delay
            ),
            Transition(
                AgentState.IDLE, Event.HIGH_RISK_DETECTED,
                AgentState.EXTRACT,
                self._on_enter_extract
            ),

            # CONFUSE transitions
            Transition(
                AgentState.CONFUSE, Event.NEW_MESSAGE,
                AgentState.CONFUSE,
                self._stay_confused
            ),
            Transition(
                AgentState.CONFUSE, Event.HIGH_RISK_DETECTED,
                AgentState.EXTRACT,
                self._on_enter_extract
            ),
            Transition(
                AgentState.CONFUSE, Event.SCAMMER_ANGRY,
                AgentState.DELAY,
                self._on_enter_delay
            ),

            # DELAY transitions
            Transition(
                AgentState.DELAY, Event.NEW_MESSAGE,
                AgentState.DELAY,
                self._extend_delay
            ),
            Transition(
                AgentState.DELAY, Event.HIGH_RISK_DETECTED,
                AgentState.EXTRACT,
                self._on_enter_extract
            ),
            Transition(
                AgentState.DELAY, Event.MEDIUM_RISK_DETECTED,
                AgentState.EXTRACT,
                self._on_enter_extract
            ),
            Transition(
                AgentState.DELAY, Event.ENTITY_EXTRACTED,
                AgentState.EXTRACT,
                self._on_enter_extract
            ),
            Transition(
                AgentState.DELAY, Event.TIMEOUT,
                AgentState.SAFE_EXIT,
                self._on_enter_safe_exit
            ),

            # EXTRACT transitions
            Transition(
                AgentState.EXTRACT, Event.NEW_MESSAGE,
                AgentState.EXTRACT,
                self._continue_extraction
            ),
            Transition(
                AgentState.EXTRACT, Event.LOW_RISK_DETECTED,
                AgentState.DELAY,
                self._on_enter_delay
            ),
            Transition(
                AgentState.EXTRACT, Event.SCAMMER_ANGRY,
                AgentState.SAFE_EXIT,
                self._on_enter_safe_exit
            ),
            Transition(
                AgentState.EXTRACT, Event.TIMEOUT,
                AgentState.SAFE_EXIT,
                self._on_enter_safe_exit
            ),

            # SAFE_EXIT transitions
            Transition(
                AgentState.SAFE_EXIT, Event.NEW_MESSAGE,
                AgentState.SAFE_EXIT,
                self._final_exit
            ),
            Transition(
                AgentState.SAFE_EXIT, Event.MANUAL_EXIT,
                AgentState.IDLE,
                self._reset_context
            ),
        ]

    # State entry actions
    def _on_enter_delay(self, context: AgentContext, event_data: dict):
        """Called when entering DELAY state"""
        context.state = AgentState.DELAY

    def _on_enter_extract(self, context: AgentContext, event_data: dict):
        """Called when entering EXTRACT state"""
        context.state = AgentState.EXTRACT
        if 'entities' in event_data:
            context.extracted_intelligence.extend(event_data['entities'])

    def _on_enter_safe_exit(self, context: AgentContext, event_data: dict):
        """Called when entering SAFE_EXIT state"""
        context.state = AgentState.SAFE_EXIT

    def _stay_confused(self, context: AgentContext, event_data: dict):
        """Action when staying in CONFUSE state"""
        pass

    def _extend_delay(self, context: AgentContext, event_data: dict):
        """Action when extending DELAY state"""
        context.message_count += 1

    def _continue_extraction(self, context: AgentContext, event_data: dict):
        """Action when continuing EXTRACT state"""
        if 'entities' in event_data:
            context.extracted_intelligence.extend(event_data['entities'])
        context.message_count += 1

    def _final_exit(self, context: AgentContext, event_data: dict):
        """Final exit action"""
        context.message_count += 1

    def _reset_context(self, context: AgentContext, event_data: dict):
        """Reset context after conversation ends"""
        context.state = AgentState.IDLE
        context.messages = []
        context.extracted_intelligence = []
        context.message_count = 0
        context.risk_history = []

    def get_context(self, session_id: str) -> AgentContext:
        """Get or create context for a session"""
        if session_id not in self.contexts:
            self.contexts[session_id] = AgentContext(session_id)
        return self.contexts[session_id]

    def process_event(
        self,
        session_id: str,
        event: Event,
        event_data: Optional[dict] = None
    ) -> AgentContext:
        """
        Process an event and transition state

        Args:
            session_id: Session identifier
            event: Event to process
            event_data: Additional event data

        Returns:
            Updated agent context
        """
        event_data = event_data or {}
        context = self.get_context(session_id)
        current_state = context.state

        # Find matching transition
        for transition in self.transitions:
            if (
                transition.from_state == current_state and
                transition.event == event
            ):
                # Execute transition
                context.state = transition.to_state
                if transition.action:
                    transition.action(context, event_data)

                # Record state change for intelligence
                context.messages.append({
                    'event': event.value,
                    'from_state': current_state.value,
                    'to_state': transition.to_state.value,
                    'timestamp': datetime.utcnow().isoformat() + "Z"
                })

                break

        return context

    def analyze_message_and_transition(
        self,
        session_id: str,
        message: str,
        risk_score: float,
        entities: Optional[List[dict]] = None
    ) -> AgentContext:
        """
        Analyze message risk and trigger appropriate transition

        Args:
            session_id: Session identifier
            message: Message text
            risk_score: Calculated risk score (0-1)
            entities: Extracted entities

        Returns:
            Updated agent context
        """
        context = self.get_context(session_id)

        # Add to message history
        context.messages.append({
            'role': 'scammer',
            'content': message,
            'timestamp': datetime.utcnow().isoformat() + "Z"
        })
        context.risk_history.append(risk_score)

        # Determine event based on risk score
        event_data = {'entities': entities or []}

        if risk_score >= 0.7:
            event = Event.HIGH_RISK_DETECTED
        elif risk_score >= 0.4:
            event = Event.MEDIUM_RISK_DETECTED
        else:
            event = Event.LOW_RISK_DETECTED

        if entities:
            event = Event.ENTITY_EXTRACTED

        # Process the event
        return self.process_event(session_id, event, event_data)

    def get_response(self, context: AgentContext) -> str:
        """
        Generate response based on current state

        Args:
            context: Current agent context

        Returns:
            Response message appropriate for the state
        """
        import random

        if context.state == AgentState.IDLE:
            responses = [
                "Hello? Who is this?",
                "I'm not sure I received the full message.",
                "Can you repeat that?",
            ]
        elif context.state == AgentState.CONFUSE:
            responses = [
                "I'm sorry, I don't understand. What do you mean?",
                "Could you explain that differently?",
                "I'm a bit confused. Can you start over?",
                "That doesn't make sense to me. What exactly are you asking?",
                "I think there might be a misunderstanding.",
            ]
        elif context.state == AgentState.DELAY:
            responses = [
                "Let me check on that. Can you give me a few minutes?",
                "I need to verify some information first. Can you wait?",
                "This sounds important. Let me make sure I understand correctly.",
                "I'll need to discuss this with someone. Can you call back later?",
                "I want to make sure I do this right. Give me some time.",
            ]
        elif context.state == AgentState.EXTRACT:
            responses = [
                "I'd love to help! Can you tell me more about yourself?",
                "This is interesting. What's your name and how did you get my number?",
                "I want to learn more. Where are you calling from?",
                "Could you walk me through this step by step?",
                "I need to be sure this is legitimate. Can you provide more details?",
            ]
        elif context.state == AgentState.SAFE_EXIT:
            responses = [
                "I'm sorry, I think I made a mistake. I can't help with this.",
                "I need to go now. Goodbye.",
                "This doesn't seem right. I'm going to end this conversation.",
                "I don't think I can assist with this. Take care.",
                "I've realized I'm not able to help. Goodbye.",
            ]
        else:
            responses = ["I'm not sure what to say."]

        return random.choice(responses)

    def get_intelligence_summary(self, session_id: str) -> dict:
        """
        Get extracted intelligence for a session

        Args:
            session_id: Session identifier

        Returns:
            Intelligence summary dictionary
        """
        context = self.get_context(session_id)

        # Filter messages to get only state transitions
        states_visited = []
        for m in context.messages:
            if isinstance(m, dict) and 'to_state' in m:
                states_visited.append(m['to_state'])

        return {
            'session_id': session_id,
            'total_messages': context.message_count,
            'states_visited': states_visited,
            'extracted_intelligence': context.extracted_intelligence,
            'risk_history': context.risk_history,
            'duration_seconds': (
                datetime.utcnow() - context.entry_time
            ).total_seconds(),
            'final_state': context.state.value,
        }

    def cleanup_session(self, session_id: str):
        """Remove session context"""
        if session_id in self.contexts:
            del self.contexts[session_id]

