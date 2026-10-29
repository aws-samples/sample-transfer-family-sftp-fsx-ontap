#!/usr/bin/env node
import 'source-map-support/register';
import { App, Validations } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { resolveEnv } from '../lib/config';
import { buildApp } from '../lib/app';
import { applyNagSuppressions } from '../lib/nag';

const app = new App();
const stacks = buildApp(app, resolveEnv((k) => app.node.tryGetContext(k)));

// cdk-nag (AWS Solutions rules) runs on every synth; accepted findings are acknowledged
// with a written reason in lib/nag.ts. Any new, unacknowledged finding fails the synth.
Validations.of(app).addPlugins(new AwsSolutionsChecks(app, { verbose: true }));
applyNagSuppressions(stacks);

app.synth();
