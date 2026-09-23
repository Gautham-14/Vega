export let currentPersona = 'Operator';

export function setPersona(persona: string) {
  currentPersona = persona;
}

export async function aegisFetch(endpoint: string, options: RequestInit = {}) {
  const url = `http://127.0.0.1:8000${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    'X-Aegis-Actor': currentPersona,
    ...(options.headers || {}),
  };

  const response = await fetch(url, { ...options, headers });
  
  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    data = text;
  }

  if (!response.ok) {
    throw new Error(`Aegis API Error (${response.status}): ${typeof data === 'string' ? data : JSON.stringify(data)}`);
  }

  return data;
}
