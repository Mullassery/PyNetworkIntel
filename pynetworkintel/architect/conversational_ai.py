"""Conversational AI interface for architectural guidance."""
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ConversationalArchitect:
    """Natural language conversational interface for architecture."""

    def __init__(self, knowledge_base, review_engine, recommendation_engine):
        """
        Initialize conversational architect.

        Args:
            knowledge_base: KnowledgeBase instance
            review_engine: ReviewEngine instance
            recommendation_engine: RecommendationEngine instance
        """
        self.knowledge_base = knowledge_base
        self.review_engine = review_engine
        self.recommendation_engine = recommendation_engine
        self.conversation_history = []
        self.current_context = {}

    def chat(self, user_message: str) -> str:
        """Process user message and generate response."""
        # Add to history
        self.conversation_history.append({
            "role": "user",
            "content": user_message,
        })

        # Classify question
        question_type = self._classify_question(user_message)

        # Generate response based on type
        if question_type == "service_inquiry":
            response = self._handle_service_inquiry(user_message)
        elif question_type == "architecture_review":
            response = self._handle_architecture_review(user_message)
        elif question_type == "pattern_recommendation":
            response = self._handle_pattern_recommendation(user_message)
        elif question_type == "cost_optimization":
            response = self._handle_cost_optimization(user_message)
        elif question_type == "roadmap":
            response = self._handle_roadmap_request(user_message)
        else:
            response = self._handle_general_inquiry(user_message)

        # Add response to history
        self.conversation_history.append({
            "role": "assistant",
            "content": response,
        })

        return response

    def _classify_question(self, user_message: str) -> str:
        """Classify the type of question."""
        message_lower = user_message.lower()

        if any(word in message_lower for word in ["service", "aws", "azure", "gcp", "lambda"]):
            return "service_inquiry"
        elif any(word in message_lower for word in ["review", "assess", "audit", "score"]):
            return "architecture_review"
        elif any(word in message_lower for word in ["pattern", "design", "architecture", "best practice"]):
            return "pattern_recommendation"
        elif any(word in message_lower for word in ["cost", "budget", "optimize", "save"]):
            return "cost_optimization"
        elif any(word in message_lower for word in ["roadmap", "timeline", "phase", "implement"]):
            return "roadmap"
        else:
            return "general"

    def _handle_service_inquiry(self, message: str) -> str:
        """Handle service-related questions."""
        # Extract service name
        services = self.knowledge_base.get_all_services()

        for service in services:
            if service.lower() in message.lower():
                info = self.knowledge_base.get_service_info(service)
                if info:
                    return f"**{service}** is a {info.get('category')} service that {info.get('description')}. " \
                           f"It's commonly used for {', '.join(info.get('use_cases', []))}."

        return "I can help with AWS, Azure, or GCP services. Which service are you interested in?"

    def _handle_architecture_review(self, message: str) -> str:
        """Handle architecture review requests."""
        return "I'd be happy to review your architecture. Please share details about:" \
               "\n- Current components and services\n- Availability requirements\n- Security needs\n- Budget constraints"

    def _handle_pattern_recommendation(self, message: str) -> str:
        """Handle pattern recommendation requests."""
        patterns = self.knowledge_base.get_all_patterns()

        return f"I can help design architectures using these patterns:\n" + \
               "\n".join([f"- {p}" for p in patterns]) + \
               "\n\nTell me about your requirements and I'll suggest the best pattern."

    def _handle_cost_optimization(self, message: str) -> str:
        """Handle cost optimization inquiries."""
        return "Here are key ways to optimize cloud costs:\n" \
               "- Use serverless for variable workloads\n" \
               "- Purchase reserved instances for baseline capacity\n" \
               "- Implement auto-scaling\n" \
               "- Right-size your resources\n" \
               "- Use spot instances for non-critical work\n\n" \
               "What's your primary cost concern?"

    def _handle_roadmap_request(self, message: str) -> str:
        """Handle roadmap generation requests."""
        return "I can create a phased implementation roadmap for you. Please provide:\n" \
               "- Current state of your infrastructure\n" \
               "- Target state (goals)\n" \
               "- Budget and timeline\n" \
               "- Team size and skills\n\n" \
               "Share these details and I'll generate a detailed roadmap."

    def _handle_general_inquiry(self, message: str) -> str:
        """Handle general inquiries."""
        return "I'm your AI infrastructure architect. I can help you with:\n" \
               "- Cloud service selection and architecture design\n" \
               "- Architecture reviews and assessments\n" \
               "- Pattern recommendations\n" \
               "- Cost optimization strategies\n" \
               "- Implementation roadmaps\n\n" \
               "What would you like to explore?"

    def get_context_awareness(self) -> Dict[str, Any]:
        """Get current conversation context."""
        return {
            "message_count": len(self.conversation_history),
            "current_context": self.current_context,
            "conversation_topics": self._extract_topics(),
        }

    def _extract_topics(self) -> List[str]:
        """Extract topics from conversation history."""
        topics = []

        for msg in self.conversation_history:
            content = msg["content"].lower()

            if "aws" in content:
                topics.append("AWS")
            if "azure" in content:
                topics.append("Azure")
            if "gcp" in content or "google" in content:
                topics.append("GCP")
            if "cost" in content or "budget" in content:
                topics.append("Cost Optimization")

        return list(set(topics))

    def reset_context(self):
        """Reset conversation context."""
        self.conversation_history = []
        self.current_context = {}

    def get_conversation_summary(self) -> str:
        """Summarize conversation."""
        topics = self._extract_topics()

        return f"Conversation Summary:\n" \
               f"- Messages: {len(self.conversation_history)}\n" \
               f"- Topics covered: {', '.join(topics) if topics else 'None yet'}\n" \
               f"- Context: {self.current_context}"
