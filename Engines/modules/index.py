import os
import git
import sys
from pathlib import Path
import json
from typing import (
    Any,
    Dict,
    Literal,
    Mapping,
    Never,
    Optional,
    Sequence,
    Tuple,
    Union,
    overload,
)
from functools import cache
from abc import ABC
from importlib import import_module
from copy import deepcopy

from dataclasses import dataclass, asdict

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.indexing.indexer import indexer
from Engines.modules.logs import log
from Engines.modules.patching import Tide2Patching

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))
class IndexTide:
    """
    Helper class for callable Index related functions. Designed to power
    `DataTide` initialization routine.
    """
    @staticmethod
    def reload():
        """Force a re-import of the tide module to refresh the in-memory index.

        DataTide is implemented as a self-initializing dataclass that captures
        the repository index at import time and then remains static. When the
        underlying index changes during a long-running process (for example
        during orchestration), calling this function removes the module from
        ``sys.modules`` so a subsequent import will re-run the module top-level
        code and create a fresh DataTide instance using the updated index.

        This method has the side effect of re-executing module import-time
        actions; callers should ensure that it is safe to reload the module in
        their runtime environment.
        """
        log("WARNING", "DataTide re-indexation")
        log("INFO", "The repository will be reindexed to update DataTide")
        del sys.modules["Engines.modules.tide"]
        from Engines.modules.tide import DataTide

    @cache #Memoization as load() is called multiple times as DataTide initializes
    @staticmethod
    def load() -> Dict[str, dict]:
        """Load the OpenTide instance index from disk or generate it in memory.

        The loader will:
        1. Load or generate the base index
        2. Reconcile with staging index if present and load fresh configurations

        Returns:
            A dictionary representing the full TIDE index structure with fresh 
            configurations from staging reconciliation.

        Raises:
            Exception: If the index cannot be loaded or generated in memory.
        """
        EXPECTED_INDEX_PATH = ROOT / "index.json"
        INDEX_PATH = Path(os.getenv("INDEX_PATH") or EXPECTED_INDEX_PATH)

        print("📂 Index not found in memory, first seeking index file...")
        if os.path.isfile(INDEX_PATH):
            _tide_index = json.load(open(INDEX_PATH))
        else:
            # Generate index in memory
            print("💽 Could not find index file, generating it in memory")
            _tide_index = indexer()
            if not _tide_index:
                raise Exception("INDEX COULD NOT BE LOADED IN MEMORY")
        
        # Reconcile with staging index if present
        _tide_index = IndexTide.reconcile_staging(_tide_index)
        return _tide_index

    @staticmethod
    def reconcile_staging(index):
        """Merge staging index model data into the provided production index.

        If a staging index exists (``staging_index.json`` by default or as
        specified by ``STAGING_INDEX_PATH``), this routine will:
        
        1. Load the staging index
        2. Merge model data (MDRs) from staging into production, where:
           - New MDRs from staging are added
           - MDRs with higher version in staging replace production versions
        3. Load fresh configurations from TOML files

        Args:
            index: The production index dictionary to reconcile against.

        Returns:
            A new index dictionary that contains reconciled model data and fresh
            configurations.
        """
        log("INFO", "Entering staging index reconciliation routine")
        EXPECTED_STAGING_INDEX_PATH = ROOT / "staging_index.json"
        STAGING_INDEX_PATH = os.getenv("STAGING_INDEX_PATH") or EXPECTED_STAGING_INDEX_PATH

        if not os.path.exists(STAGING_INDEX_PATH):
            log("SKIP", "No Staging Index to reconcile")
            return index

        from Engines.modules.files import resolve_configurations
        RECONCILED_INDEX = index.copy()
        STG_INDEX = json.load(open(Path(STAGING_INDEX_PATH)))
        added_mdr = list()
        updated_mdr = list()

        patch = Tide2Patching()

        for mdr in STG_INDEX:
            if mdr not in RECONCILED_INDEX["objects"]["mdr"]:
                log("INFO", "Patching MDR in staging index", mdr)
                RECONCILED_INDEX["objects"]["mdr"][mdr] = patch.tide_1_patch(STG_INDEX[mdr], "mdr")
                added_mdr.append(mdr)
            else:
                main_mdr_metadata = (
                    RECONCILED_INDEX["objects"]["mdr"][mdr].get("meta") or RECONCILED_INDEX["objects"]["mdr"][mdr]["metadata"]
                )
                main_version = main_mdr_metadata["version"]
                stg_mdr_metadata = (
                    STG_INDEX[mdr].get("meta") or STG_INDEX[mdr]["metadata"]
                )
                stg_version = stg_mdr_metadata["version"]

                mdr_name = (
                    STG_INDEX[mdr].get("name")
                    or STG_INDEX[mdr]["title"].split("$")[0].strip()
                )

                if stg_version > main_version:
                    log("INFO",
                        f"🔄 Replacing MDR {mdr_name} from prod index with"
                        f" staging data, as version is higher (main : v{main_version}"
                        f" staging : v{stg_version})"
                    )
                    log("INFO", "Doing a safety patching to avoid edge cases")
                    RECONCILED_INDEX["objects"]["mdr"][mdr] = patch.tide_1_patch(STG_INDEX[mdr], "mdr")
                    updated_mdr.append(mdr)
        
        # Always load fresh configurations after model data reconciliation
        log("INFO", "Loading fresh configurations from TOML files")
        RECONCILED_INDEX["configurations"] = resolve_configurations()
        
        log("SUCCESS", "Finalized Staging Reconciliation Routine")
        log("INFO", "Updated MDRs from Production Index with Staging Data", str(len(updated_mdr)))
        log("INFO", "New MDR added from Staging Data ", str(len(added_mdr)))
        return RECONCILED_INDEX

    @staticmethod
    def compute_chains(tvm_index: dict) -> dict:
        """Compute chaining relationships between threat vector models (TVMs).

        This function inspects the provided TVM index and builds a mapping of
        TVM UUIDs to their chaining relations. The returned structure maps each
        TVM to another mapping where keys are relation names and values are
        lists of vectors (UUIDs) that are linked under that relation.

        Args:
            tvm_index: A dictionary where keys are TVM identifiers and values
                contain a ``threat`` key which may include a ``chaining`` list.

        Returns:
            A dictionary of the form {tvm_id: {relation: [vector_id, ...]}}
            only for TVMs that include chaining definitions.
        """

        chain = dict()
        for tvm in (n := tvm_index):
            if "chaining" in n[tvm]["threat"]:
                if tvm not in chain:
                    chain[tvm] = dict()
                for link in n[tvm]["threat"]["chaining"]:
                    if link["relation"] not in chain[tvm]:
                        chain[tvm][link["relation"]] = []
                    if link["vector"] not in chain[tvm][link["relation"]]:
                        chain[tvm][link["relation"]].append(link["vector"])

        return chain

    @staticmethod
    def return_paths(tier: Literal["all", "core", "tide"]) -> dict[str, Path]:
        """Return pre-computed path mappings from the index for the requested tier.

        Args:
            tier: One of ``"all"``, ``"core"``, or ``"tide"`` specifying the
                scope of paths to return.

        Returns:
            A dict mapping logical path names to Path objects for the requested
            tier. ``"all"`` returns the full paths mapping, while ``"core"``
            and ``"tide"`` return the respective sub-mapping.
        """

        if tier == "all":
            return IndexTide.load()["paths"]
        if tier == "core":
            return IndexTide.load()["paths"]["core"]
        if tier == "tide":
            return IndexTide.load()["paths"]["tide"]

                
