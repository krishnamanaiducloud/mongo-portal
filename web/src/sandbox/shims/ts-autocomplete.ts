// Build-time replacement for @mongodb-js/mongodb-ts-autocomplete, mongosh's
// TypeScript-language-service autocompleter. It depends on the TypeScript
// compiler and file system access and does not work in the browser sandbox;
// the sandbox selects mongosh's classic completer (USE_NEW_AUTOCOMPLETE=0),
// so this module is never instantiated.
export class MongoDBAutocompleter {
  constructor() {
    throw new Error('The TypeScript autocompleter is not available in the portal shell');
  }
}

export default { MongoDBAutocompleter };
