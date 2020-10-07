import { Aspect, defineAspects, Hint } from './operation';
import { CommandOperation, CommandOperationOptions } from './command';
import type { Callback } from '../utils';
import type { Document } from '../bson';
import type { Server } from '../sdam/server';
import type { Collection } from '../collection';

/** @public */
export interface EstimatedDocumentCountOptions extends CommandOperationOptions {
  skip?: number;
  limit?: number;
  hint?: Hint;
}

/** @internal */
export class EstimatedDocumentCountOperation
  extends CommandOperation<number>
  implements EstimatedDocumentCountOptions {
  collectionName: string;
  query?: Document;

  skip?: number;
  limit?: number;
  hint?: Hint;

  constructor(collection: Collection, options: EstimatedDocumentCountOptions);
  constructor(collection: Collection, query: Document, options: EstimatedDocumentCountOptions);
  constructor(
    collection: Collection,
    query?: Document | EstimatedDocumentCountOptions,
    options?: EstimatedDocumentCountOptions
  ) {
    if (typeof options === 'undefined') {
      options = query as EstimatedDocumentCountOptions;
      query = undefined;
    }

    super(collection, options);
    this.collectionName = collection.collectionName;
    if (query) {
      this.query = query;
    }
  }

  execute(server: Server, callback: Callback<number>): void {
    const cmd: Document = { count: this.collectionName };

    if (this.query) {
      cmd.query = this.query;
    }

    if (typeof this.skip === 'number') {
      cmd.skip = this.skip;
    }

    if (typeof this.limit === 'number') {
      cmd.limit = this.limit;
    }

    if (this.hint) {
      cmd.hint = this.hint;
    }

    super.executeCommand(server, cmd, (err, response) => {
      if (err) {
        callback(err);
        return;
      }

      callback(undefined, response.n || 0);
    });
  }
}

defineAspects(EstimatedDocumentCountOperation, [Aspect.READ_OPERATION, Aspect.RETRYABLE]);
