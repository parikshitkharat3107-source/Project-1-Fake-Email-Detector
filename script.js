 // Email Analysis Engine
        class EmailAnalyzer {
            constructor() {
                this.urgencyPhrases = [
                    'urgent', 'immediate action', 'suspended', 'verify now', 'act now', 
                    'expire', 'limited time', 'click here', 'confirm identity', 
                    'unusual activity', 'your account will be closed', 'temporary hold',
                    'security breach', 'unauthorized access', 'reset your password',
                    'verify your identity', 'confirm your account', 'update your information',
                    'action required', 'respond immediately', 'within 24 hours', 'within 48 hours'
                ];

                this.threatPhrases = [
                    'will be closed', 'will be suspended', 'will be terminated',
                    'will lose access', 'legal action', 'account locked'
                ];

                this.phishingDomains = [
                    'secure-bank', 'verify-account', 'paypal-secure', 'apple-id',
                    'account-update', 'security-alert', 'customer-service', 
                    'support-team', 'no-reply', 'noreply', 'admin', 'help-desk',
                    'notification', 'alert', 'service','won gift', 'claim-prize','Congratulations! You have been selected as the lucky winner', 'lottery', 'prize', 'inheritance',
                    'Your email ID has won a cash prize!', 'urgent response needed to claim your reward'

                ];

                this.domainSpoofing = [
                    {fake: 'paypa1', real: 'paypal'}, 
                    {fake: 'amaz0n', real: 'amazon'}, 
                    {fake: 'app1e', real: 'apple'},
                    {fake: 'micros0ft', real: 'microsoft'}, 
                    {fake: 'g00gle', real: 'google'}
                ];

                this.urlShorteners = [
                    'bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'tiny.cc', 'rb.gy'
                ];

                this.suspiciousTlds = [
                    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work','.pictures', '.click', '.country', '.stream', '.download'
                ];

                this.personalInfoKeywords = [
                    'ssn', 'social security', 'password', 'credit card', 'pin code',
                    'pin number', 'bank account', 'account number', 'routing number',
                    'cvv', 'security code', 'date of birth', "mother's maiden",
                    'verify your identity', 'confirm your password', 'enter your credentials','otp'
                ];

                this.moneyPhrases = [
                    'wire transfer', 'send money', 'gift card', 'bitcoin',
                    'cryptocurrency', 'payment required', 'pay now', 'invoice'
                ];

                this.scamPhrases = [
                    'you have won', 'congratulations', 'claim your prize',
                    'lottery winner', 'inheritance', 'beneficiary','won gift', 'claim-prize','Congratulations! You have been selected as the lucky winner', 'lottery', 'prize', 'inheritance',
                    'Your email ID has won a cash prize!', 'urgent response needed to claim your reward'
                ];

                this.genericGreetings = [
                    'dear customer', 'dear user', 'dear member', 'dear client',
                    'valued customer', 'hello user', 'dear sir/madam'
                ];

                this.misspellings = [
                    'acount', 'verfiy', 'secruity', 'payemnt', 'recieve', 'occured',
                    'verifcation', 'authroization', 'confrim'
                ];
            }

            analyze(sender, subject, body, links) {
                console.log('Starting analysis...');
                console.log('Sender:', sender);
                console.log('Subject:', subject);
                console.log('Body:', body.substring(0, 100) + '...');
                
                const indicators = [];
                let suspiciousScore = 0;
                const text = `${sender} ${subject} ${body} ${links}`.toLowerCase();

                // Analyze sender
                const senderResult = this.analyzeSender(sender);
                indicators.push(...senderResult.indicators);
                suspiciousScore += senderResult.score;
                console.log('Sender analysis - Score:', senderResult.score, 'Indicators:', senderResult.indicators.length);

                // Analyze subject
                const subjectResult = this.analyzeSubject(subject);
                indicators.push(...subjectResult.indicators);
                suspiciousScore += subjectResult.score;
                console.log('Subject analysis - Score:', subjectResult.score, 'Indicators:', subjectResult.indicators.length);

                // Analyze body
                const bodyResult = this.analyzeBody(body, text);
                indicators.push(...bodyResult.indicators);
                suspiciousScore += bodyResult.score;
                console.log('Body analysis - Score:', bodyResult.score, 'Indicators:', bodyResult.indicators.length);

                // Analyze links
                const linksResult = this.analyzeLinks(links, text);
                indicators.push(...linksResult.indicators);
                suspiciousScore += linksResult.score;
                console.log('Links analysis - Score:', linksResult.score, 'Indicators:', linksResult.indicators.length);

                // Calculate trust score
                const trustScore = Math.max(0, Math.round(100 - Math.min(suspiciousScore, 100)));
                console.log('Total suspicious score:', suspiciousScore);
                console.log('Trust score:', trustScore);

                // Determine verdict
                let verdict, message;
                if (trustScore >= 70) {
                    verdict = 'safe';
                    message = 'This email appears to be legitimate';
                } else if (trustScore >= 40) {
                    verdict = 'suspicious';
                    message = 'This email shows suspicious characteristics - BE CAUTIOUS';
                } else {
                    verdict = 'dangerous';
                    message = 'HIGH RISK: This email is likely a phishing/scam attempt';
                }

                if (indicators.length === 0) {
                    indicators.push({type: 'safe', text: 'No obvious phishing indicators detected'});
                }

                console.log('Final verdict:', verdict);
                console.log('Total indicators:', indicators.length);

                return {verdict, score: trustScore, message, indicators};
            }

            analyzeSender(sender) {
                const indicators = [];
                let score = 0;
                const senderLower = sender.toLowerCase();

                // Check domain spoofing
                this.domainSpoofing.forEach(({fake, real}) => {
                    if (senderLower.includes(fake)) {
                        indicators.push({
                            type: 'danger',
                            text: `Domain spoofing: looks like "${real}" but uses "${fake}"`
                        });
                        score += 30;
                    }
                });

                // Check suspicious domains
                const legitimate = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com'];
                this.phishingDomains.forEach(domain => {
                    if (senderLower.includes(domain) && !legitimate.some(leg => senderLower.includes(leg))) {
                        indicators.push({
                            type: 'danger',
                            text: `Suspicious domain pattern: "${domain}" (often used in phishing)`
                        });
                        score += 20;
                    }
                });

                // Check for excessive numbers
                const username = sender.split('@')[0];
                if (/[0-9]{3,}/.test(username)) {
                    indicators.push({
                        type: 'warning',
                        text: 'Sender name contains many numbers (common in phishing)'
                    });
                    score += 10;
                }

                return {indicators, score};
            }

            analyzeSubject(subject) {
                const indicators = [];
                let score = 0;
                const subjectLower = subject.toLowerCase();

                // Check urgency
                const foundUrgency = this.urgencyPhrases.filter(phrase => subjectLower.includes(phrase));
                if (foundUrgency.length > 0) {
                    indicators.push({
                        type: 'warning',
                        text: `Uses ${foundUrgency.length} urgency tactic(s): "${foundUrgency.slice(0, 2).join('", "')}"`
                    });
                    score += Math.min(foundUrgency.length * 10, 30);
                }

                // Check threats
                const foundThreats = this.threatPhrases.filter(phrase => subjectLower.includes(phrase));
                if (foundThreats.length > 0) {
                    indicators.push({
                        type: 'danger',
                        text: 'Contains threatening language'
                    });
                    score += 20;
                }

                // Check excessive caps
                const capsRatio = (subject.match(/[A-Z]/g) || []).length / Math.max(subject.length, 1);
                if (capsRatio > 0.5 && subject.length > 10) {
                    indicators.push({
                        type: 'warning',
                        text: 'Excessive use of capital letters (SHOUTING)'
                    });
                    score += 10;
                }

                return {indicators, score};
            }

            analyzeBody(body, text) {
                const indicators = [];
                let score = 0;

                // Check personal info requests
                const foundPii = this.personalInfoKeywords.filter(kw => text.includes(kw));
                if (foundPii.length > 0) {
                    indicators.push({
                        type: 'danger',
                        text: `Requests sensitive info: ${foundPii.slice(0, 3).join(', ')}`
                    });
                    score += Math.min(foundPii.length * 15, 40);
                }

                // Check money requests
                const foundMoney = this.moneyPhrases.filter(phrase => text.includes(phrase));
                if (foundMoney.length > 0) {
                    indicators.push({
                        type: 'danger',
                        text: `Money-related request: ${foundMoney.slice(0, 2).join(', ')}`
                    });
                    score += 25;
                }

                // Check scam phrases
                const foundScams = this.scamPhrases.filter(phrase => text.includes(phrase));
                if (foundScams.length > 0) {
                    indicators.push({
                        type: 'danger',
                        text: 'Contains prize/lottery/inheritance scam indicators'
                    });
                    score += 30;
                }

                // Check generic greetings
                if (this.genericGreetings.some(greeting => text.includes(greeting))) {
                    indicators.push({
                        type: 'warning',
                        text: 'Uses generic greeting (no personalization)'
                    });
                    score += 10;
                }

                // Check spelling errors
                const foundMisspellings = this.misspellings.filter(word => text.includes(word));
                if (foundMisspellings.length > 0) {
                    indicators.push({
                        type: 'warning',
                        text: `Contains ${foundMisspellings.length} spelling error(s)`
                    });
                    score += Math.min(foundMisspellings.length * 5, 15);
                }

                return {indicators, score};
            }

            analyzeLinks(links, text) {
                const indicators = [];
                let score = 0;

                if (!links && !text.match(/https?:\/\//)) {
                    return {indicators, score};
                }

                const allText = `${links} ${text}`.toLowerCase();

                // Check URL shorteners
                if (this.urlShorteners.some(shortener => allText.includes(shortener))) {
                    indicators.push({
                        type: 'danger',
                        text: 'Contains URL shorteners (hides real destination)'
                    });
                    score += 25;
                }

                // Check IP addresses
                if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(allText)) {
                    indicators.push({
                        type: 'danger',
                        text: 'URL uses IP address instead of domain name'
                    });
                    score += 30;
                }

                // Check suspicious TLDs
                if (this.suspiciousTlds.some(tld => allText.includes(tld))) {
                    indicators.push({
                        type: 'warning',
                        text: 'Uses suspicious/free top-level domain'
                    });
                    score += 20;
                }

                return {indicators, score};
            }
        }

        // UI Controller
        const form = document.getElementById('emailForm');
        const analyzeBtn = document.getElementById('analyzeBtn');
        const resultContainer = document.getElementById('resultContainer');
        const verdictCard = document.getElementById('verdictCard');
        const verdictIcon = document.getElementById('verdictIcon');
        const verdictMessage = document.getElementById('verdictMessage');
        const scoreFill = document.getElementById('scoreFill');
        const scoreValue = document.getElementById('scoreValue');
        const indicatorList = document.getElementById('indicatorList');

        const analyzer = new EmailAnalyzer();

        // Make sure DOM is fully loaded
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Email Detector loaded');
        });

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            console.log('Form submitted');

            const sender = document.getElementById('sender').value.trim();
            const subject = document.getElementById('subject').value.trim();
            const body = document.getElementById('body').value.trim();
            const links = document.getElementById('links').value.trim();

            // Validate inputs
            if (!sender || !body) {
                alert('Please fill in sender email and body text');
                return;
            }

            // Show loading state
            analyzeBtn.disabled = true;
            analyzeBtn.innerHTML = '<span class="btn-content"><div class="spinner"></div><span>Analyzing...</span></span>';
            resultContainer.classList.remove('show');

            // Simulate processing time
            await new Promise(resolve => setTimeout(resolve, 1500));

            // Perform analysis
            const result = analyzer.analyze(sender, subject, body, links);
            console.log('Analysis result:', result);

            // Display results
            displayResults(result);

            // Reset button
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = `
                <span class="btn-content">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
                        <polyline points="22,6 12,13 2,6"></polyline>
                    </svg>
                    <span>Analyze Email</span>
                </span>
            `;
        });

        // Also add click handler as backup
        analyzeBtn.addEventListener('click', function(e) {
            console.log('Button clicked');
        });

        function displayResults(result) {
            console.log('Displaying results:', result);
            
            // Set verdict card styling
            verdictCard.className = `verdict-card ${result.verdict}`;
            
            // Set icon based on verdict with proper SVG structure
            if (result.verdict === 'safe') {
                verdictIcon.innerHTML = `
                    <circle cx="12" cy="12" r="10" stroke="#22c55e" fill="none"></circle>
                    <polyline points="9 12 11 14 15 10" stroke="#22c55e" fill="none"></polyline>
                `;
            } else if (result.verdict === 'suspicious') {
                verdictIcon.innerHTML = `
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" stroke="#eab308" fill="none"></path>
                    <line x1="12" y1="9" x2="12" y2="13" stroke="#eab308"></line>
                    <line x1="12" y1="17" x2="12.01" y2="17" stroke="#eab308" stroke-width="2"></line>
                `;
            } else {
                verdictIcon.innerHTML = `
                    <circle cx="12" cy="12" r="10" stroke="#ef4444" fill="none"></circle>
                    <line x1="12" y1="8" x2="12" y2="12" stroke="#ef4444"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16" stroke="#ef4444" stroke-width="2"></line>
                `;
            }

            // Set message
            verdictMessage.textContent = result.message;
            console.log('Verdict message set to:', result.message);

            // Reset and animate score
            scoreFill.style.width = '0%';
            scoreFill.className = `score-fill ${result.verdict}`;
            
            setTimeout(() => {
                scoreFill.style.width = `${result.score}%`;
                scoreValue.textContent = `${result.score}%`;
                console.log('Score animated to:', result.score);
            }, 100);

            // Display indicators
            indicatorList.innerHTML = '';
            console.log('Indicators:', result.indicators);
            
            result.indicators.forEach((indicator, index) => {
                const li = document.createElement('li');
                li.className = 'indicator-item';
                li.innerHTML = `
                    <span class="indicator-dot ${indicator.type}"></span>
                    <span class="indicator-text">${indicator.text}</span>
                `;
                indicatorList.appendChild(li);
                console.log(`Added indicator ${index + 1}:`, indicator.text);
            });

            // Force show results container
            resultContainer.style.display = 'block';
            resultContainer.classList.add('show');
            
            // Scroll to results
            setTimeout(() => {
                resultContainer.scrollIntoView({behavior: 'smooth', block: 'nearest'});
            }, 200);
            
            console.log('Results displayed successfully');
        }