"""
ML Model Module for Scam Detection
TF-IDF Vectorizer + Logistic Regression for text classification
"""

import os
import pickle
import re
from typing import List, Tuple, Optional
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import numpy as np


class ScamDetectionModel:
    """
    TF-IDF + Logistic Regression model for scam detection.

    Features:
    - TF-IDF vectorization with n-grams
    - Logistic Regression classifier with probability output
    - Built-in training data for common scam patterns
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the scam detection model.

        Args:
            model_path: Optional path to saved model pickle file
        """
        self.model_path = model_path or self._default_model_path()
        self.pipeline: Optional[Pipeline] = None
        self.is_trained = False

        # Try to load existing model or create new one
        self._initialize_model()

    def _default_model_path(self) -> str:
        """Get default path for saved model"""
        base_dir = Path(__file__).parent.parent
        return str(base_dir / "models" / "scam_model.pkl")

    def _initialize_model(self):
        """Initialize or load the model"""
        # Create models directory if it doesn't exist
        models_dir = Path(self.model_path).parent
        models_dir.mkdir(parents=True, exist_ok=True)

        # Try to load existing model
        if os.path.exists(self.model_path):
            try:
                self._load_model()
                return
            except Exception as e:
                print(f"Warning: Could not load model from {self.model_path}: {e}")

        # Create new model
        self._create_model()
        self._train_with_builtin_data()

    def _create_model(self):
        """Create a new TF-IDF + Logistic Regression pipeline"""
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 3),  # unigrams, bigrams, trigrams
                min_df=2,
                max_df=0.95,
                sublinear_tf=True,
                strip_accents='unicode',
                analyzer='word',
                token_pattern=r'\w{1,}',
                stop_words='english'
            )),
            ('classifier', LogisticRegression(
                C=1.0,
                class_weight='balanced',
                solver='lbfgs',
                max_iter=1000,
                random_state=42,
                n_jobs=-1
            ))
        ])
        self.is_trained = False

    def _load_model(self):
        """Load model from pickle file"""
        with open(self.model_path, 'rb') as f:
            self.pipeline = pickle.load(f)
        self.is_trained = True

    def save_model(self):
        """Save model to pickle file"""
        if self.pipeline is None:
            raise ValueError("No model to save")

        with open(self.model_path, 'wb') as f:
            pickle.dump(self.pipeline, f)

    def _preprocess_text(self, text: str) -> str:
        """
        Preprocess text for classification

        Args:
            text: Raw input text

        Returns:
            Preprocessed text
        """
        # Convert to lowercase
        text = text.lower()

        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()

        # Keep alphanumeric and important punctuation
        text = re.sub(r'[^\w\s.,!?]', ' ', text)

        return text

    def _train_with_builtin_data(self):
        """
        Train model with built-in scam detection dataset
        Based on common scam patterns and linguistic features
        """
        # Scam message samples (labeled as scam)
        scam_samples = [
            "urgent your bank account has been blocked immediately call this number",
            "congratulations you have won a lottery prize send your bank details to claim",
            "your parcel is held customs pay fee immediately or it will be returned",
            "irs notice outstanding tax warrant arrest imminent pay now",
            "social security number suspended verify identity immediately",
            "amazon your account has been hacked reset password now",
            "apple id verification required your device is locked",
            "microsoft support your computer has a virus call now",
            "job offer work from home 5000 per week send processing fee",
            "investment opportunity high returns limited time invest now",
            "bitcoin doubling your money send cryptocurrency to this address",
            "prince needs help transferring millions please send bank details",
            "romance scam love you forever send money for plane ticket",
            "grandchild in jail bail money needed wire transfer",
            "utility bill overdue service will be disconnected pay today",
            "medical emergency family member hospital need money now",
            "government grant approved send processing fee to receive",
            "car warranty expired extend coverage call now",
            "free vacation prize claim by sending credit card details",
            "payday loan approved instant approval send ssn",
            "student loan forgiveness apply now before deadline",
            "roof damage repair insurance claim send deposit",
            "wedding venue booking send deposit to reserve date",
            "pet adoption fee shipping cost send money order",
            "crypto wallet verification required connect your account",
            "online dating profile beautiful woman wants to meet send gifts",
            "forex trading signals guaranteed profits subscribe monthly",
            "binary options trading 100% return investment required",
            "mlm business opportunity earn passive income recruit others",
            "pyramid scheme join now limited spots available",
            "nigerian prince inheritance millions need help transfer",
            "western union scam send money to claim prize",
            "fake check scam deposit check send money back",
            "phishing email bank login verify account immediately",
            "smishing sms fraud text message link to fake website",
            "vishing voice call pretending to be bank representative",
            "tech support scam pop up virus detected call number",
            "refund scam fake refund overpayment return difference",
            "romance scam long distance relationship gift cards",
            "gift card scam buy gift cards send codes",
            "sextortion scam private photos threaten to release",
            "catfishing fake profile online dating scam",
            "employment scam fake job interview background check fee",
            "rental scam fake apartment listing send security deposit",
            "charity scam fake disaster relief donations",
            "government impersonator fake irs social security call",
            "business email compromise fake ceo wire transfer",
            "ransomware attack pay bitcoin to recover files",
            "fake invoice scam overdue payment immediate action",
            "subscription trap free trial hidden charges",
            "identity theft warning fake data breach notification",
        ]

        # Legitimate message samples (labeled as safe)
        safe_samples = [
            "hello how are you doing today",
            "meeting scheduled for tomorrow at 3pm",
            "thanks for your email i will review and respond",
            "your order has been shipped tracking number included",
            "appointment confirmed for next week monday",
            "project update timeline extended by one week",
            "please find attached the requested document",
            "happy birthday hope you have a wonderful day",
            "welcome to our newsletter unsubscribe anytime",
            "password reset request click link to create new password",
            "order delivery expected within 5 business days",
            "your payment has been processed successfully",
            "account statement available for download",
            "subscription renewed thank you for your business",
            "weather forecast sunny skies expected tomorrow",
            "recipe for dinner今晚 let's cook together",
            "book recommendation fiction novel recent release",
            "gym membership renewal automatic on monthly basis",
            "insurance policy renewal quote available online",
            "medical appointment reminder next tuesday",
            "school schedule parent teacher conference week",
            "restaurant reservation confirmed for two guests",
            "flight booking reference number included",
            "hotel reservation confirmation booking code",
            "car rental pickup at airport terminal",
            "package delivery attempt tomorrow between 9am 5pm",
            "bank transaction statement monthly summary",
            "credit card payment due soon minimum amount due",
            "investment portfolio quarterly performance report",
            "tax documents ready for filing available online",
            "utility bill account balance and payment options",
            "phone bill itemized charges and usage summary",
            "internet service provider plan upgrade options",
            "cable television channel lineup and pricing",
            "grocery store weekly specials and discounts",
            " pharmacy prescription ready for pickup",
            "library book due return or renew online",
            "school cafeteria lunch menu next week",
            "community event park cleanup saturday morning",
            "volunteer opportunity local shelter needs help",
            "donation receipt charitable contribution tax deductible",
            "pet vaccination clinic saturday free microchipping",
            "car maintenance oil change recommended mileage",
            "home improvement project planning renovation",
            "moving checklist change of address updates",
            "new neighbor welcome introduce ourselves",
            "coffee meetup saturday morning downtown cafe",
            "book club discussion next book title announced",
            "exercise class registration open sign up now",
            "cooking class upcoming schedule registration",
            "language learning group meetup beginners welcome",
        ]

        # Combine and create labels
        texts = scam_samples + safe_samples
        labels = [1] * len(scam_samples) + [0] * len(safe_samples)

        # Train the model
        self.pipeline.fit(texts, labels)
        self.is_trained = True

        # Save the model
        self.save_model()

    def predict_proba(self, text: str) -> Tuple[float, float]:
        """
        Predict probability of scam vs safe

        Args:
            text: Message text to classify

        Returns:
            Tuple of (scam_probability, safe_probability)
        """
        if not self.is_trained:
            raise ValueError("Model is not trained")

        processed_text = self._preprocess_text(text)
        probabilities = self.pipeline.predict_proba([processed_text])[0]

        # Assuming classes are [safe, scam] based on training order
        return probabilities[1], probabilities[0]

    def predict(self, text: str) -> Tuple[int, float]:
        """
        Predict class and confidence

        Args:
            text: Message text to classify

        Returns:
            Tuple of (class_label, confidence)
            1 = scam, 0 = safe
        """
        scam_prob, _ = self.predict_proba(text)
        prediction = 1 if scam_prob >= 0.5 else 0
        confidence = max(scam_prob, 1 - scam_prob)
        return prediction, confidence

    def get_scam_indicators(self, text: str) -> List[str]:
        """
        Identify which scam indicators triggered

        Args:
            text: Message text to analyze

        Returns:
            List of triggered indicator keywords
        """
        indicators = []
        text_lower = text.lower()

        # Urgency indicators
        urgency_words = [
            'urgent', 'immediately', 'asap', 'right now', 'dont delay',
            'time limit', 'deadline', 'act now', 'hurry', 'limited time'
        ]

        # Threat indicators
        threat_words = [
            'blocked', 'suspended', 'arrest', 'police', 'legal action',
            'warrant', 'jail', 'prison', 'investigation', 'fraud alert',
            'account compromised', 'hacked', 'unauthorized'
        ]

        # Request indicators
        request_words = [
            'send money', 'wire transfer', 'gift card', 'bitcoin',
            'bank details', 'password', 'pin', 'otp', 'verify identity',
            'click here', 'call this number', 'share information'
        ]

        # Reward indicators
        reward_words = [
            'won', 'winner', 'prize', 'lottery', 'jackpot', 'congratulations',
            'selected', 'chosen', 'free', 'bonus', 'cash prize'
        ]

        for word in urgency_words:
            if word in text_lower:
                indicators.append(f"urgency: {word}")
                break

        for word in threat_words:
            if word in text_lower:
                indicators.append(f"threat: {word}")
                break

        for word in request_words:
            if word in text_lower:
                indicators.append(f"request: {word}")
                break

        for word in reward_words:
            if word in text_lower:
                indicators.append(f"reward: {word}")
                break

        return indicators

    def classify_scam_type(self, text: str, scam_prob: float) -> str:
        """
        Classify the type of scam based on keywords

        Args:
            text: Message text
            scam_prob: Scam probability score

        Returns:
            Scam classification string
        """
        if scam_prob < 0.5:
            return "Not Scam"

        text_lower = text.lower()

        # Banking scams
        banking_keywords = ['bank', 'account', 'blocked', 'suspended', 'verify',
                          'fraud', 'transaction', 'atm', 'card', 'debit', 'credit']
        if any(kw in text_lower for kw in banking_keywords):
            return "Bank Fraud"

        # Lottery/Prize scams
        lottery_keywords = ['won', 'winner', 'lottery', 'prize', 'jackpot',
                          'congratulations', 'selected', 'million']
        if any(kw in text_lower for kw in lottery_keywords):
            return "Lottery/Prize Scam"

        # IRS/Government scams
        government_keywords = ['irs', 'tax', 'government', 'social security',
                             'medicare', 'irs', 'federal']
        if any(kw in text_lower for kw in government_keywords):
            return "Government Impersonation"

        # Tech support scams
        tech_keywords = ['computer', 'virus', 'tech support', 'microsoft',
                        'apple', 'windows', 'hacked', ' malware', 'infected']
        if any(kw in text_lower for kw in tech_keywords):
            return "Tech Support Scam"

        # Job scams
        job_keywords = ['job', 'work from home', 'salary', 'hiring', 'employment',
                       'career', 'recruiter', 'interview']
        if any(kw in text_lower for kw in job_keywords):
            return "Job Offer Scam"

        # Romance scams
        romance_keywords = ['love', 'relationship', 'dating', 'heart', 'miss you',
                          'beautiful', 'handsome', 'soulmate']
        if any(kw in text_lower for kw in romance_keywords):
            return "Romance Scam"

        # Investment/Crypto scams
        investment_keywords = ['investment', 'bitcoin', 'crypto', 'trading',
                             'returns', 'profit', 'double', 'guaranteed']
        if any(kw in text_lower for kw in investment_keywords):
            return "Investment/Crypto Scam"

        # Default classification
        return "General Scam"

    def get_classification_details(self, text: str) -> dict:
        """
        Get full classification details for a message

        Args:
            text: Message text to classify

        Returns:
            Dictionary with classification results
        """
        scam_prob, safe_prob = self.predict_proba(text)
        prediction, confidence = self.predict(text)
        indicators = self.get_scam_indicators(text)
        scam_type = self.classify_scam_type(text, scam_prob)

        return {
            'is_scam': bool(prediction),
            'scam_probability': float(scam_prob),
            'safe_probability': float(safe_prob),
            'confidence': float(confidence),
            'indicators': indicators,
            'scam_type': scam_type
        }

