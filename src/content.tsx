import { createRoot } from 'react-dom/client'
import { StrictMode } from 'react'
import ContentPage from '@/components/ContentPage'

// Create the root element in the main document
const root = document.createElement('div')
document.body.append(root)

// Create the shadow root for the element
const shadowRoot = root.attachShadow({ mode: 'open' });

// Create a <link> element to include an external stylesheet
const styleElement = document.createElement('link');
styleElement.rel = 'stylesheet';
styleElement.href = chrome.runtime.getURL('tailwind.css');


// Append the <link> element to the shadow root
shadowRoot.appendChild(styleElement);

root.style.cssText = 'all:initial'
// Render the React component in the shadow DOM
createRoot(shadowRoot).render(
    <StrictMode>
        <div id='outreachmate'>
            <ContentPage />
        </div>
    </StrictMode>
);
