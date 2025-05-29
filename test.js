import { GenerativeModel } from '@google/generative-ai';

async function generateText() {
  const apiKey = 'YOUR_API_KEY';
  GenerativeModel.setApiKey(apiKey);

  const model = new GenerativeModel({ model: 'gemini-pro-vision' });

  const response = await model.generateContent({
    prompt: 'Write a poem about a cat.'
  });

  console.log(response.text);
}

generateText();