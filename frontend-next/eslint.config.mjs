// PRA-308: ESLint flat config for Next 16 (which removed `next lint`).
// eslint-config-next 16 ships a native flat config (core-web-vitals + typescript); we
// import and spread it directly so the ruleset is unchanged from the previous
// `.eslintrc.json` — only the config format + invocation (`eslint` vs `next lint`) changed.
import next from 'eslint-config-next';

const eslintConfig = [
  { ignores: ['.next/**', 'node_modules/**', 'next-env.d.ts'] },
  ...next,
  {
    // PRA-308: Next 16's eslint-config-next newly enables the React Compiler /
    // react-hooks v6 rule family as ERRORS (set-state-in-effect, static-components,
    // immutability, purity, refs, preserve-manual-memoization). These were NOT enforced
    // under Next 15.5's ruleset; adopting them is a codebase-wide hooks refactor with
    // behavior risk — out of scope for a dependency refresh. Neutralize them here to
    // preserve the prior effective lint behavior. The classic rules-of-hooks and
    // exhaustive-deps checks stay active. Follow-up: enable + remediate these in a
    // dedicated frontend slice.
    rules: {
      'react-hooks/set-state-in-effect': 'off',
      'react-hooks/static-components': 'off',
      'react-hooks/immutability': 'off',
      'react-hooks/purity': 'off',
      'react-hooks/refs': 'off',
      'react-hooks/preserve-manual-memoization': 'off',
    },
  },
];

export default eslintConfig;
