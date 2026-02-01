import React, { useState, useEffect } from 'react';
import { analyzeMessage } from '../services/geminiservices';
import { AnalysisResult, HistoryItem } from '../types.ts';
import AnalysisView from '../components/AnalysisView';
import EndpointTester from '../components/EndpointTester';

// ...existing code...
