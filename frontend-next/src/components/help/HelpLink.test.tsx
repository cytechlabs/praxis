import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import HelpLink from './HelpLink';

describe('HelpLink', () => {
  it('opens bundled help in a separate tab without opener access', () => {
    const html = renderToStaticMarkup(<HelpLink slug="packages" />);

    expect(html).toContain('href="/help/packages"');
    expect(html).toContain('target="_blank"');
    expect(html).toContain('rel="noopener noreferrer"');
  });
});
