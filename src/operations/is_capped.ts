import type { Callback } from '../utils';
import type { Collection } from '../collection';
import { OperationOptions, OperationBase } from './operation';
import type { Server } from '../sdam/server';
import { MongoError } from '..';

/** @internal */
export class IsCappedOperation extends OperationBase<boolean> implements OperationOptions {
  collection: Collection;

  constructor(collection: Collection, options: OperationOptions) {
    super(options);
    this.collection = collection;
  }

  execute(server: Server, callback: Callback<boolean>): void {
    const coll = this.collection;

    coll.s.db.listCollections({ name: coll.collectionName }, this).toArray((err, collections) => {
      if (err || !collections) return callback(err);
      if (collections.length === 0) {
        return callback(new MongoError(`collection ${coll.namespace} not found`));
      }

      const collOptions = collections[0].options;
      callback(undefined, !!(collOptions && collOptions.capped));
    });
  }
}
