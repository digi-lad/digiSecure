/**
 * This is the backend serverless function with a live connection to the Gemini API.
 * File path: /api/analyze.js
 *
 * It receives data from the frontend, constructs a detailed prompt, sends it to the Gemini API,
 * and then forwards the AI's structured response back to the frontend.
 */

// We need to import the Google Generative AI SDK.
// In your Vercel project, you'll need to add `@google/generative-ai` to your package.json dependencies.
import { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } from "@google/generative-ai";

// Initialize the AI model
// The API key is securely accessed from Vercel's environment variables.
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ 
    model: "gemini-1.5-flash",
    // We define a strict JSON schema for the AI's response to ensure consistency.
    generationConfig: {
        responseMimeType: "application/json",
        responseSchema: {
            type: "OBJECT",
            properties: {
                verdict: { type: "STRING", enum: ["SCAM", "NOT A SCAM", "UNCERTAIN"] },
                confidence: { type: "NUMBER" },
                reason: { type: "STRING" },
                red_flags: { type: "ARRAY", items: { type: "STRING" } },
                advice: { type: "STRING" }
            },
            required: ["verdict", "confidence", "reason", "advice"]
        }
    }
});

// These settings are to prevent the model from blocking responses due to the content of the scams themselves.
const safetySettings = [
    { category: HarmCategory.HARM_CATEGORY_HARASSMENT, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold: HarmBlockThreshold.BLOCK_NONE },
];


// Helper function to convert Base64 image data to a format the API understands
function fileToGenerativePart(base64Data, mimeType) {
    return {
        inlineData: {
            data: base64Data.split(',')[1], // Remove the "data:image/jpeg;base64," prefix
            mimeType
        },
    };
}


// The main handler for the serverless function
export default async function handler(req, res) {
    if (req.method !== 'POST') {
        res.setHeader('Allow', ['POST']);
        return res.status(405).end(`Method ${req.method} Not Allowed`);
    }

    try {
        const { text, url, imageBase64 } = req.body;

        if (!text && !url && !imageBase64) {
            return res.status(400).json({ error: 'No content provided for analysis.' });
        }

        // --- Construct the Prompt for the AI ---
        const promptParts = [
            'You are an expert scam analyst. Analyze the following information provided by a user who suspects it might be a scam. Provide your analysis in the required JSON format.',
            'Here is the information to analyze:'
        ];

        if (text) {
            promptParts.push(`Pasted Text: "${text}"`);
        }
        if (url) {
            promptParts.push(`URL included: "${url}"`);
        }
        
        const imageParts = [];
        if (imageBase64) {
            // Assuming the frontend sends a data URL like "data:image/png;base64,..."
            const mimeType = imageBase64.substring(imageBase64.indexOf(":") + 1, imageBase64.indexOf(";"));
            imageParts.push(fileToGenerativePart(imageBase64, mimeType));
            promptParts.push('A screenshot is also attached for analysis.');
        }

        const fullPrompt = promptParts.join('\n\n');

        // --- Call the Gemini API ---
        const result = await model.generateContent([fullPrompt, ...imageParts], { safetySettings });
        
        // The response from the model is already a JSON object because of our schema definition.
        const aiResponse = result.response.candidates[0].content.parts[0].text;
        
        // Send the AI's structured response back to the frontend.
        res.status(200).json(JSON.parse(aiResponse));

    } catch (error) {
        console.error('Error in analysis function:', error);
        res.status(500).json({ 
            verdict: 'ERROR',
            confidence: 100,
            reason: 'An error occurred while communicating with the AI. This could be due to a configuration issue or invalid input.',
            red_flags: ['API Error'],
            advice: 'Please check the server logs for more details. Ensure your API key is configured correctly in the Vercel environment variables.'
         });
    }
}
