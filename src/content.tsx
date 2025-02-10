import { createRoot } from 'react-dom/client'
import { StrictMode } from 'react'
import ContentPage from '@/components/ContentPage'
import css from './index.css?inline'

const onLoaded = () => {
    const root = document.createElement('div')
    document.body.prepend(root)
    const shadowRoot = root.attachShadow({ mode: 'open' })

    const renderIn = document.createElement('div')
    shadowRoot.appendChild(renderIn)

    createRoot(renderIn).render(
        <StrictMode>
            <style type="text/css">{css}</style>
            <ContentPage />
        </StrictMode>,
    )
}

if (document.readyState === 'complete') {
    onLoaded()
} else {
    window.addEventListener('load', () => {
        onLoaded()
    })
}
