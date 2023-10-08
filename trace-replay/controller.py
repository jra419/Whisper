#!/usr/bin/env python3

import os
import sys
import signal
import logging
import argparse
import time
import yaml
from eval_metrics import eval_whisper
from pipeline_whisper import PipelineWhisper

logger = None

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="peregrine-py")
    argparser.add_argument('-p', '--plugin', type=str, help='Plugin')
    argparser.add_argument('-c', '--conf', type=str, help='Config path')
    args = argparser.parse_args()

    with open(args.conf, "r") as yaml_conf:
        conf = yaml.load(yaml_conf, Loader=yaml.FullLoader)

    # configure logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(args.plugin)

    start = time.time()

    # Call function to run the packet processing pipeline.
    if args.plugin == 'whisper':
        pipeline = PipelineWhisper(conf['trace'], conf['labels'], conf['sampling'],
                                   conf['train_size'], conf['dst_mac'])

    pipeline.process()

    stop = time.time()
    total_time = stop - start

    print('Complete. Time elapsed: ', total_time)

    # Call function to perform eval/csv.
    if args.plugin == 'whisper':
        eval_whisper(pipeline.stats_global, conf['attack'], conf['sampling'], total_time)

    # exit (bug workaround)
    logger.info("Exiting!")

    # flush logs, stdout, stderr
    logging.shutdown()
    sys.stdout.flush()
    sys.stderr.flush()

    # exit (bug workaround)
    os.kill(os.getpid(), signal.SIGTERM)
