"""
Main function for the ATLAS project.  It is used to run any particular experiment

Usage:
$>python main.py {SCRAPING | ANALYSIS | CHALLENGE} <arguments>

SCRAPING usage: scraps the web, according to a formatted input file, for detecting FIDO2 usage
$>python main.py SCRAPING -i <target_input_file>
Accepted values
    <target_input_file>: TEST, TRANCO, UMBRELLA, CRUX, GROUNDTRUTH

ANALYSIS usage: plots various results for atlas (requires GenericPlotting)
$>python main.py ANALYSIS -m <metric> [-e <extension>]
Accepted values:
    <metric>: GROUNDTRUTH, SCRAPING, ...
    <extension>: PDF, PNG, EPS (optional -- PDF by default)

CHALLENGE usage: captures FIDO2 behavior
$>python main.py CHALLENGE -i <fido2_urls>
Accepted values
    <fido2_urls> TEST, FIDO2
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__))) # Normally, should not be modified unless the directory tree is indeed modified

from import_data import *

async def handle_scraping(args):
    """
    Handles the SCRAPING arguments

    Params:
        args: the CLI arguments
    """
    # Parse optional CLI arguments

    # resume in case of failure?
    resume = bool(getattr(args, "resume", False))

    # dump_every might be None or a string — convert properly
    dump_freq = getattr(args, "dump_every", None)
    dump_freq = int(dump_freq) if dump_freq else DUMP_EVERY

    # Log for clarity
    logger.info(f"Starting atlas scraping | resume={resume} | dump_freq={dump_freq}")

    # --- Run scraper ---
    df_split = getattr(args, "parallel", None)
    if not df_split:
        await non_parallel_run_atlas(args, resume=resume, dump_freq=dump_freq)
    else:
        # checking if folders are created
        os.makedirs("results", exist_ok=True)
        os.makedirs("raw_results", exist_ok=True)
        df_split = int(df_split)
        await parallel_run_atlas(args, resume=resume, dump_freq=dump_freq, df_split=df_split)

def handle_analysis(args):
    """
    Handles the ANALYSIS arguments

    Params:
        args: the CLI arguments
    """
    logger.info(f"[ANALYSIS] Metric: {args.metric}")
    if getattr(args, "metric", None):
        run_data_analysis(args)
    else:
        run_determinism_analysis(args)

async def handle_challenge(args):
    """
    Handles the CHALLENGE arguments

    Params:
        args: the CLI arguments
    """
    # Parse optional CLI arguments

    # resume in case of failure?
    resume = bool(getattr(args, "resume", False))

    # dump_every might be None or a string — convert properly
    dump_freq = getattr(args, "dump_every", None)
    dump_freq = int(dump_freq) if dump_freq else DUMP_EVERY

    # Log for clarity
    logger.info(
        f"Starting FIDO2 capture | resume={resume} | dump_freq={dump_freq}"
    )

    # Run scraper
    await run_capture(args, resume=resume, dump_freq=dump_freq)

def _create_parser():
    """
    Builds CLI arguments parser
    """
    logger.info(f"Création du parser CLI...")
    parser = argparse.ArgumentParser(description="Main command parser.")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # SCRAPING command
    scraping_parser = subparsers.add_parser("SCRAPING", help="Handle Atlas authentication inference input")
    scraping_parser.add_argument(
        "-i", "--input", required=True, help="Input file (TEST, GROUNDTRUTH, DATASET_0, DATASET_1, DATASET_2, DATASET_3)"
        )
    scraping_parser.add_argument(
        "-r", "--resume", action='store_true', help="Restart scraping after a failure"
        )
    scraping_parser.add_argument(
        "-d", "--dump_every", required=False, help="Number of sites to process before dumping to CSV (500 by default)"
        )
    scraping_parser.add_argument(
        "-p", "--parallel", required=False, help="Number of processes for parallelizing scraper"
        )
    scraping_parser.set_defaults(func=handle_scraping)

    # ANALYSIS command
    plot_parser = subparsers.add_parser(
        "ANALYSIS", help="Handle data analysis input"
        )
    plot_parser.add_argument(
        "-m", "--metric", required=False, help="Analysis to be performed (CHALLENGE, GROUNDTRUTH, SCRAPING, ETHICS)"
        )
    plot_parser.set_defaults(func=handle_analysis)

    # CHALLENGE command
    challenge_parser = subparsers.add_parser(
        "CHALLENGE", help="Handle FIDO2 Challenge input"
    )
    challenge_parser.add_argument(
        "-i", "--input", required=True, help="Input file (TEST, FIDO2)"
    )
    challenge_parser.add_argument(
        "-r", "--resume", action='store_true',
        help="Restart scraping after a failure"
    )
    challenge_parser.add_argument(
        "-d", "--dump_every", required=False,
        help="Number of sites to process before dumping (500 by default)"
    )
    challenge_parser.set_defaults(func=handle_challenge)

    return parser

def main():
    """
    Main function.
    """
    logger.info("Début de l'exécution")
    parser = _create_parser()
    args = parser.parse_args()

    result = args.func(args)

    if inspect.iscoroutine(result):

        async def runner():
            loop = asyncio.get_running_loop()

            def async_exception_handler(loop, context):
                exception = context.get("exception")
                message = context.get("message")

                if exception:
                    logger.error(f"[ASYNC UNHANDLED] {repr(exception)}")
                else:
                    logger.error(f"[ASYNC UNHANDLED] {message}")

            loop.set_exception_handler(async_exception_handler)

            return await result

        asyncio.run(runner())

if __name__ == "__main__":
    main()
