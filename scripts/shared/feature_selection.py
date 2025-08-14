#!/usr/bin/env python3
"""
Feature Selection Utilities
Sophisticated feature selection for anomaly detection using coverage, cardinality, and entropy analysis
"""

import logging
from typing import Dict, List, Any, Tuple
import numpy as np

def analyze_feature_quality(feature_stats: Dict[str, Dict[str, Any]], 
                          training_samples: int,
                          target_features: int = 10,
                          min_coverage: float = 0.6,
                          logger: logging.Logger = None) -> List[str]:
    """
    Analyze and select optimal features based on coverage, cardinality, and information content
    
    Args:
        feature_stats: Feature statistics dictionary from model metadata
        training_samples: Total number of training samples
        target_features: Target number of features to select (default: 7)
        min_coverage: Minimum coverage threshold (default: 0.7 = 70%)
        logger: Logger instance for debugging
    
    Returns:
        List of selected feature names, ordered by quality score
    """
    if logger is None:
        logger = logging.getLogger(__name__)
        
    feature_scores = []
    
    for feature, stats in feature_stats.items():
        # Skip is_business_hours entirely - we don't want to use it
        if feature == 'is_business_hours':
            continue
            
        # Calculate coverage (how often this feature appears)
        if stats['type'] == 'categorical':
            total_feature_samples = sum(stats['value_counts'].values()) if 'value_counts' in stats else 0
        else:
            # For numerical features, assume they're always present if in stats
            total_feature_samples = training_samples
        
        coverage = total_feature_samples / training_samples if training_samples > 0 else 0
        
        # Skip very sparse features
        if coverage < min_coverage:
            logger.debug(f"Skipping {feature}: coverage {coverage:.3f} < min_coverage {min_coverage}")
            continue
            
        # Calculate cardinality
        if stats['type'] == 'categorical':
            cardinality = stats.get('unique_count', len(stats.get('value_counts', {})))
        else:
            # For numerical features, use a reasonable estimate
            cardinality = min(1000, training_samples // 10)
        
        # Skip constant features or extremely high cardinality
        if cardinality < 2 or cardinality > 1000:
            continue
        
        # Calculate information content (entropy-like measure)
        if stats['type'] == 'categorical':
            value_counts = stats.get('value_counts', {})
            total = sum(value_counts.values())
            if total > 0:
                # Calculate normalized entropy (0 = all same value, 1 = uniform distribution)
                entropy = -sum((count/total) * np.log2(count/total) for count in value_counts.values() if count > 0)
                max_entropy = np.log2(len(value_counts)) if len(value_counts) > 1 else 1
                normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0
            else:
                normalized_entropy = 0
        else:
            # For numerical features, assume reasonable entropy
            normalized_entropy = 0.7
        
        # Score feature (higher is better)
        # Prefer good coverage, moderate cardinality, high information content
        cardinality_score = min(1.0, cardinality / 100)  # Sweet spot around 10-100 unique values
        if cardinality > 100:
            cardinality_score = max(0.1, 1.0 - (cardinality - 100) / 900)  # Penalize very high cardinality
        
        # Give temporal features (hour, day_of_week) bonus for MVP temporal discrimination
        temporal_bonus = 0.2 if feature in ['hour', 'day_of_week'] else 0.0
        
        score = (coverage * 0.4) + (cardinality_score * 0.3) + (normalized_entropy * 0.3) + temporal_bonus
        
        feature_scores.append((feature, score, coverage, cardinality, normalized_entropy))
    
    # Sort by score 
    feature_scores.sort(key=lambda x: x[1], reverse=True)
    
    # Remove redundant features
    deduped_features = []
    for feature, score, coverage, cardinality, entropy in feature_scores:
        # Skip redundant temporal features
        if feature == 'hour_of_day' and any(f[0] == 'hour' for f in deduped_features):
            continue  # hour_of_day is identical to hour
        if feature == 'is_business_hours':
            # Skip is_business_hours if we already have hour OR day_of_week (it's derivable)
            has_hour = any(f[0] == 'hour' for f in deduped_features)
            has_day_of_week = any(f[0] == 'day_of_week' for f in deduped_features)
            if has_hour or has_day_of_week:
                continue
        
        deduped_features.append((feature, score, coverage, cardinality, entropy))
        
        if len(deduped_features) >= target_features:
            break
    
    selected_features = [f[0] for f in deduped_features]
    
    # Ensure we have at least one numerical feature for Isolation Forest
    # Force include temporal features if no numerical features were selected
    numerical_features_selected = [f for f in selected_features if feature_stats.get(f, {}).get('type') == 'numerical']
    if len(numerical_features_selected) == 0:
        logger.warning("No numerical features selected, forcing inclusion of temporal features")
        # Add temporal features if they exist in stats
        for temporal_feature in ['hour', 'day_of_week']:
            if temporal_feature in feature_stats and temporal_feature not in selected_features:
                selected_features.append(temporal_feature)
                logger.info(f"Force-added {temporal_feature} as required numerical feature")
                if len(selected_features) >= target_features:
                    break
        
        # If we exceeded target_features, remove some categorical features  
        if len(selected_features) > target_features:
            categorical_features_selected = [f for f in selected_features if feature_stats.get(f, {}).get('type') == 'categorical']
            # Remove the lowest scoring categorical features
            features_to_remove = len(selected_features) - target_features
            for feature in categorical_features_selected[-features_to_remove:]:
                selected_features.remove(feature)
                logger.debug(f"Removed {feature} to maintain target feature count")
    
    logger.info(f"Feature selection completed: {len(selected_features)} features selected")
    logger.debug(f"Selected features with scores:")
    for feature, score, coverage, cardinality, entropy in deduped_features:
        if feature in selected_features:
            logger.debug(f"  {feature}: score={score:.3f} coverage={coverage:.2f} cardinality={cardinality} entropy={entropy:.3f}")
    
    # Final debug logging
    final_numerical = [f for f in selected_features if feature_stats.get(f, {}).get('type') == 'numerical']
    final_categorical = [f for f in selected_features if feature_stats.get(f, {}).get('type') == 'categorical']
    logger.info(f"Final selection: {len(final_categorical)} categorical + {len(final_numerical)} numerical = {len(selected_features)} total")
    
    if len(selected_features) == 0:
        logger.warning(f"No features selected! Total features checked: {len(feature_stats)}, min_coverage: {min_coverage}")
        # Print coverage for all features to debug
        for feature, stats in feature_stats.items():
            if stats['type'] == 'categorical':
                total_samples = sum(stats['value_counts'].values()) if 'value_counts' in stats else 0
            else:
                total_samples = training_samples
            coverage = total_samples / training_samples if training_samples > 0 else 0
            logger.warning(f"  {feature}: coverage={coverage:.3f} type={stats['type']}")
    
    return selected_features


def select_features_for_training(categorical_features: List[str], 
                                numerical_features: List[str],
                                feature_stats: Dict[str, Dict[str, Any]],
                                training_samples: int,
                                target_features: int = 10,
                                min_coverage: float = 0.6,
                                logger: logging.Logger = None) -> Tuple[List[str], List[str]]:
    """
    Select optimal features for model training using the same logic as detection
    
    Args:
        categorical_features: All available categorical features
        numerical_features: All available numerical features  
        feature_stats: Feature statistics dictionary
        training_samples: Total number of training samples
        target_features: Target number of features to select (default: 7)
        min_coverage: Minimum coverage threshold (default: 0.7 = 70%)
        logger: Logger instance for debugging
    
    Returns:
        Tuple of (selected_categorical_features, selected_numerical_features)
    """
    if logger is None:
        logger = logging.getLogger(__name__)
    
    # Use the same sophisticated selection logic
    all_selected = analyze_feature_quality(
        feature_stats=feature_stats,
        training_samples=training_samples,
        target_features=target_features,
        min_coverage=min_coverage,
        logger=logger
    )
    
    # Split selected features back into categorical and numerical
    selected_categorical = [f for f in all_selected if f in categorical_features]
    selected_numerical = [f for f in all_selected if f in numerical_features]
    
    logger.info(f"Selected {len(selected_categorical)} categorical and {len(selected_numerical)} numerical features")
    
    return selected_categorical, selected_numerical